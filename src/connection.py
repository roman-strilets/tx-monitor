"""TCP connection to a Beam node.

Manages the raw socket, transparent AES-CTR encryption via
:class:`~src.secure_channel.SecureChannel`, frame-level reads and writes,
and the multi-step Login handshake required before any application-level
messages can be exchanged.
"""
import hmac as hmac_mod
import socket
import sys
import time
from collections import deque

from .codec import decode_uint, encode_uint, make_header, parse_header
from .protocol import (
    Address,
    EXTENSION_VERSION,
    HEADER_SIZE,
    MAC_SIZE,
    MAX_FRAME_SIZE,
    MessageType,
    message_name,
)
from .secure_channel import SecureChannel
from .utils import extension_bits, format_address


def build_login_payload(login_flags: int, fork_hashes: list[bytes]) -> bytes:
    """Build the binary payload for a Beam Login message.

    Encodes the requested extension version, fork hashes, and login flags
    into the compact format expected by the node.

    Args:
        login_flags: Bitmask of ``LOGIN_FLAG_*`` constants.
        fork_hashes: List of 32-byte fork-configuration hashes.

    Returns:
        Encoded Login payload bytes.
    """
    flags = login_flags | (extension_bits(EXTENSION_VERSION) << 4)
    buf = bytearray(encode_uint(len(fork_hashes)))
    for fork_hash in fork_hashes:
        buf.extend(fork_hash)
    buf.extend(encode_uint(flags))
    return bytes(buf)


def parse_login_payload(payload: bytes) -> tuple[list[bytes], int]:
    """Parse a Beam Login payload.

    The payload contains a compact hash-count, that many 32-byte fork hashes,
    and a compact flags field.

    Args:
        payload: Raw Login payload bytes.

    Returns:
        Tuple of ``(fork_hashes, flags)``.

    Raises:
        ValueError: If the payload is malformed.
    """
    try:
        count, size = decode_uint(payload)
    except IndexError as exc:
        raise ValueError("login payload is empty") from exc

    offset = size
    fork_hashes: list[bytes] = []
    for _ in range(count):
        end = offset + 32
        if end > len(payload):
            raise ValueError("login payload ended before all fork hashes were read")
        fork_hashes.append(payload[offset:end])
        offset = end

    try:
        flags, size = decode_uint(payload, offset)
    except IndexError as exc:
        raise ValueError("login payload is missing the flags field") from exc

    offset += size
    if offset != len(payload):
        raise ValueError(
            f"login payload has {len(payload) - offset} trailing byte(s)"
        )

    return fork_hashes, flags


class BeamConnection:
    """Manages a single TCP connection to a Beam node.

    Handles socket lifecycle, transparent AES-CTR frame encryption/decryption
    via :class:`~src.secure_channel.SecureChannel`, a read-ahead buffer, a
    pending-message queue (used to park messages received during the Login
    handshake), and the multi-step Login handshake itself.
    """

    def __init__(
        self,
        host: str,
        port: int,
        connect_timeout: float,
        read_timeout: float,
        verbose: bool = False,
    ):
        """Initialise connection parameters without opening a socket.

        Args:
            host: Hostname or IP address of the Beam node.
            port: TCP port of the Beam node.
            connect_timeout: Seconds to wait for the TCP handshake.
            read_timeout: Default socket read timeout in seconds.
            verbose: Emit diagnostic messages to *stderr* when ``True``.
        """
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.verbose = verbose
        self.sock: socket.socket | None = None
        self.sc = SecureChannel()
        self._buf = bytearray()
        self._pending = deque()
        self.peer_fork_hashes: list[bytes] = []
        self.peer_login_flags: int | None = None

    def _log(self, message: str):
        """Print *message* to *stderr* when verbose logging is enabled."""
        if self.verbose:
            print(message, file=sys.stderr)

    def _require_socket(self) -> socket.socket:
        """Return the open socket, raising ``RuntimeError`` if not connected."""
        if self.sock is None:
            raise RuntimeError("connection is not open")
        return self.sock

    def connect(self):
        """Open the TCP socket and apply the default read timeout."""
        self.sock = socket.create_connection(
            (self.host, self.port), timeout=self.connect_timeout
        )
        self.sock.settimeout(self.read_timeout)

    def remote_address(self) -> Address | None:
        """Return the remote ``(host, port)`` address, or ``None`` if not connected."""
        if self.sock is None:
            return None
        host, port = self.sock.getpeername()[:2]
        return host, port

    def _recv(self, size: int) -> bytes:
        """Read exactly *size* bytes from the socket into the internal buffer.

        Loops over ``sock.recv`` until the buffer holds enough data, then
        slices and removes the consumed bytes.

        Args:
            size: Number of bytes to return.

        Returns:
            Exactly *size* bytes.

        Raises:
            ConnectionError: If the remote end closes the connection before
                *size* bytes have been received.
        """
        sock = self._require_socket()
        while len(self._buf) < size:
            chunk = sock.recv(8192)
            if not chunk:
                raise ConnectionError("connection closed")
            self._buf.extend(chunk)

        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out

    def send(self, message_type: MessageType, payload: bytes = b""):
        """Encrypt and send a single Beam protocol message.

        When outgoing encryption is active the payload is appended with an
        8-byte HMAC tag before the whole frame is AES-CTR encrypted.  When
        encryption is not yet active the frame is sent in plain text.

        Args:
            message_type: Type code identifying the message.
            payload: Raw message body bytes.  Defaults to an empty payload.
        """
        sock = self._require_socket()
        if self.sc.out_on:
            header = make_header(message_type, len(payload) + MAC_SIZE)
            tag = self.sc.mac(header, payload)
            sock.sendall(self.sc.encrypt(header + payload + tag))
            return

        header = make_header(message_type, len(payload))
        sock.sendall(header + payload)

    def recv(self) -> tuple[MessageType, bytes]:
        """Read exactly one frame from the socket and return it decrypted.

        Reads the 8-byte header first, then the declared payload length.
        When incoming decryption is active the HMAC tag at the end of the
        payload is verified before any data is returned.

        Returns:
            ``(message_type, payload)`` with the MAC stripped.

        Raises:
            ValueError: On frame-size overflow or HMAC mismatch.
            ConnectionError: If the connection is closed mid-frame.
        """
        header = self.sc.decrypt(self._recv(HEADER_SIZE))
        message_type, size = parse_header(header)
        if size > MAX_FRAME_SIZE:
            raise ValueError(f"frame too large: {size}")

        body = self.sc.decrypt(self._recv(size)) if size else b""
        if self.sc.in_on:
            if size < MAC_SIZE:
                raise ValueError(f"secure frame too small: {size}")
            payload, tag = body[:-MAC_SIZE], body[-MAC_SIZE:]
            if not hmac_mod.compare_digest(tag, self.sc.mac(header, payload)):
                raise ValueError("HMAC mismatch")
            return message_type, payload

        return message_type, body

    def recv_message(self, timeout: float | None = None) -> tuple[MessageType, bytes]:
        """Return the next message, respecting an optional per-call timeout.

        Drains the pending queue first (messages queued during the Login
        handshake).  When the queue is empty, adjusts the socket timeout and
        calls :meth:`recv`.

        Args:
            timeout: Seconds to wait for the next frame from the socket.
                ``None`` blocks indefinitely; ``0`` or negative raises
                :class:`socket.timeout` immediately.

        Returns:
            ``(message_type, payload)`` pair.

        Raises:
            socket.timeout: If no message arrives within *timeout* seconds.
        """
        if self._pending:
            return self._pending.popleft()

        sock = self._require_socket()
        if timeout is None:
            sock.settimeout(None)
        else:
            if timeout <= 0:
                raise socket.timeout()
            sock.settimeout(timeout)
        return self.recv()

    def _queue_message(self, message_type: MessageType, payload: bytes):
        """Park a message in the pending queue for later retrieval via :meth:`recv_message`.

        Called during the Login handshake to hold application-level messages
        that arrive before the handshake completes.

        Args:
            message_type: Type code of the message to queue.
            payload: Decrypted message body.
        """
        self._pending.append((message_type, payload))

    def send_time(self):
        """Send the current Unix time in response to a GetTime request."""
        self.send(MessageType.TIME, encode_uint(int(time.time())))

    def handshake(self, login_flags: int, fork_hashes: list[bytes]):
        """Perform the full Beam Login handshake over this connection.

        Executes the ``SChannelInitiate → SChannelReady → Login`` sequence,
        enabling encryption in both directions.  Messages received before the
        ``Login`` confirmation are either handled inline (GetTime, Ping) or
        queued for the caller via :meth:`recv_message`.

        Args:
            login_flags: Bitmask of ``LOGIN_FLAG_*`` constants to request.
            fork_hashes: List of 32-byte fork-configuration hashes.

        Raises:
            RuntimeError: If the node replies with an unexpected message type
                or sends ``Bye`` during the handshake.
        """
        nonce = self.sc.generate_nonce()
        node = format_address((self.host, self.port))
        self._log(f"[*] {node} SChannelInitiate ->")
        self.send(MessageType.SCHANNEL_INIT, nonce)

        message_type, payload = self.recv()
        if message_type != MessageType.SCHANNEL_INIT:
            raise RuntimeError(f"expected SChannelInitiate, got 0x{message_type:02X}")
        self._log(f"[*] {node} <- SChannelInitiate")

        self.send(MessageType.SCHANNEL_READY)
        self.sc.derive_keys(payload)
        self.sc.out_on = True
        self._log(f"[*] {node} outgoing encryption on")

        self.send(MessageType.GET_TIME)
        self.send(MessageType.LOGIN, build_login_payload(login_flags, fork_hashes))

        message_type, _ = self.recv()
        if message_type != MessageType.SCHANNEL_READY:
            raise RuntimeError(f"expected SChannelReady, got 0x{message_type:02X}")

        self.sc.in_on = True
        self._log(f"[*] {node} duplex encryption on")

        saw_login = False
        while not saw_login:
            message_type, payload = self.recv()
            if message_type == MessageType.BYE:
                raise RuntimeError(
                    f"bye after login: {chr(payload[0]) if payload else '?'}"
                )
            if message_type == MessageType.GET_TIME:
                self.send_time()
                continue
            if message_type == MessageType.TIME:
                server_time, _ = decode_uint(payload)
                self._log(
                    f"[*] {node} time offset: {server_time - int(time.time()):+d}s"
                )
                continue
            if message_type == MessageType.AUTHENTICATION:
                self._log(f"[*] {node} <- Authentication")
                continue
            if message_type == MessageType.PING:
                self.send(MessageType.PONG)
                continue
            if message_type == MessageType.LOGIN:
                self._log(f"[*] {node} <- Login")
                try:
                    self.peer_fork_hashes, self.peer_login_flags = parse_login_payload(
                        payload
                    )
                except ValueError as exc:
                    raise RuntimeError(f"invalid Login payload: {exc}") from exc
                saw_login = True
                continue

            name = message_name(message_type)
            self._log(f"[*] {node} queued {name} during login")
            self._queue_message(message_type, payload)

    def close(self):
        """Send a ``Bye`` message and close the socket.

        Safe to call multiple times.  Errors while sending ``Bye`` are
        silently ignored so that partially-open connections can always be
        cleaned up.
        """
        if self.sock is None:
            return

        try:
            self.send(MessageType.BYE, b"s")
        except Exception:
            pass

        self.sock.close()
        self.sock = None