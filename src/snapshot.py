"""One-shot mempool snapshot for the Beam network.

Connects to a Beam node, performs a TLS handshake, and retrieves every
transaction the node announces via HaveTransaction messages.  Exits once the
pending queue is empty and the node has been silent for ``idle_timeout``
seconds (or sends a Bye message).
"""
import socket
import sys
import time
from dataclasses import dataclass, field

from beam_p2p import (
    Address,
    BeamConnection,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_REQUEST_TIMEOUT,
    LOGIN_FLAG_SPREADING_TRANSACTIONS,
    MessageType,
    decode_transaction_id,
    encode_transaction_id,
    format_address,
    message_name,
    utc_now_iso,
)
from beam_p2p.deserializers import deserialize_new_transaction_payload

from src.models import CaptureRecord, MonitorResult, SnapshotState
from src.storage import JsonLineWriter


@dataclass(frozen=True)
class SnapshotConfig:
    """Immutable configuration for a one-shot mempool snapshot.

    Attributes:
        endpoint: ``(host, port)`` pair identifying the Beam node.
        connect_timeout: Maximum time in seconds to wait while establishing
            the TCP connection.
        request_timeout: Maximum time in seconds to wait for a
            NewTransaction payload after sending a GetTransaction request.
            If the deadline is exceeded the monitor raises ``TimeoutError``.
        idle_timeout: Seconds of silence after the pending queue is empty
            before the snapshot is considered complete and the function
            returns.
        fork_hashes: List of raw fork-ID byte strings sent to the node
            during the Login handshake.  Pass an empty list if the node
            requires no specific fork.
        verbose: ``True`` to emit diagnostic log lines to *stderr*.
    """

    endpoint: Address
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT
    fork_hashes: list[bytes] = field(default_factory=list)
    verbose: bool = False


def _log(verbose: bool, message: str) -> None:
    """Emit a diagnostic message to stderr when verbose mode is enabled.

    This small helper centralizes conditional logging across the snapshot
    capture flow. It's intentionally lightweight because it's called from
    performance-sensitive code paths while the monitor is connected.

    Args:
        verbose: When True the message is printed to stderr.
        message: Human-readable diagnostic text.
    """
    if verbose:
        print(message, file=sys.stderr)


def _write_capture_record(
    writer: JsonLineWriter,
    endpoint: str,
    verbose: bool,
    tx_id: bytes,
    payload: bytes,
) -> None:
    """Deserialize a NewTransaction payload and persist it as a CaptureRecord.

    This function attempts to fully deserialize the raw transaction payload
    using :func:`src.deserializers.deserialize_new_transaction_payload`. If
    deserialization succeeds, the decoded representation is stored in the
    ``decoded`` field of the resulting :class:`CaptureRecord`. If
    deserialization raises, the exception message is captured in the
    ``decode_error`` field and the raw payload is still persisted (hex-
    encoded) so that no captured transaction is lost.

    Side effects:
    - Writes a single ``CaptureRecord`` via ``writer.write()``.
    - Emits optional diagnostic log lines when ``verbose`` is True.

    Args:
        writer: JSON-lines writer that accepts :class:`CaptureRecord`
            objects.
        endpoint: Human-readable node address recorded in the ``node`` field
            and used in diagnostic output.
        verbose: Controls emission of diagnostic log lines.
        tx_id: 32-byte transaction identifier (used as the record key).
        payload: Raw bytes of the NewTransaction message body.

    Notes:
        - The function always writes a ``CaptureRecord`` even if decoding
          fails.
        - IO errors from ``writer.write()`` or other unexpected exceptions
          are propagated to the caller; only deserialization exceptions are
          consumed and recorded in the output record.
    """
    decoded = None
    decode_error = None
    try:
        decoded = deserialize_new_transaction_payload(payload)
    except Exception as exc:
        decode_error = str(exc)
        _log(verbose, f"[*] {endpoint} failed to decode tx {tx_id.hex()}: {exc}")

    writer.write(
        CaptureRecord(
            node=endpoint,
            tx_id=tx_id.hex(),
            raw_payload_hex=payload.hex(),
            payload_size=len(payload),
            captured_at=utc_now_iso(),
            decoded=decoded,
            decode_error=decode_error,
        )
    )
    _log(verbose, f"[*] {endpoint} captured tx {tx_id.hex()}")


def run_snapshot(
    config: SnapshotConfig,
    writer: JsonLineWriter,
) -> MonitorResult:
    """Capture a one-shot mempool snapshot from a Beam node.

        High-level behaviour
        --------------------
        This function performs a single, non-reconnecting capture session:

        1. Establishes a TCP/TLS connection to the configured ``endpoint`` and
             completes the Beam login handshake advertising transaction spreading
             capability.
        2. Maintains a :class:`SnapshotState` that tracks announced transaction
             ids (deduplicated), a FIFO ``pending`` queue, a single ``in_flight``
             entry and a set of ``captured`` ids.
        3. Repeatedly sends ``GET_TRANSACTION`` for the next pending id when the
             state produces one, setting a ``request_deadline`` for the reply.
        4. Receives and dispatches messages using the node-side framing; on
             ``NEW_TRANSACTION`` the corresponding pending request is completed and
             a ``CaptureRecord`` is written.
        5. Terminates successfully when the pending queue is empty, no request
             is in-flight, and the node has been silent for ``config.idle_timeout``
             seconds, or when the node sends a ``BYE`` message with nothing left to
             retrieve.

        State machine and timeouts
        --------------------------
        - ``request_deadline`` is an absolute monotonic timestamp set when a
            ``GET_TRANSACTION`` is sent. If a ``NEW_TRANSACTION`` does not arrive
            before that deadline the function raises ``TimeoutError``.
        - When there is pending work the receive loop polls non-blocking
            (``wait_timeout == 0.0``) so that requests can be initiated
            immediately.
        - When there is no pending work and no ``in_flight`` request, the
            function measures idle time and returns once ``config.idle_timeout``
            seconds have elapsed without any new ``HAVE_TRANSACTION`` announcements.

        Error handling
        --------------
        - ``socket.timeout`` indicates a receive deadline; it is interpreted to
            either trigger a ``TimeoutError`` for outstanding requests or to check
            whether the snapshot idle timeout has expired.
        - ``ConnectionError`` (or other ``OSError``) indicates the connection was
            closed unexpectedly; the function returns successfully if the monitor
            is already idle, otherwise a ``RuntimeError`` is raised.
        - Deserialization errors for a specific transaction payload are recorded
            in the ``CaptureRecord.decode_error`` field; the raw payload is still
            persisted.

        Side effects
        ------------
        - Writes one ``CaptureRecord`` per successfully retrieved transaction via
            ``writer.write()``; I/O errors from the writer are propagated.

        Args:
                config: Connection settings and snapshot parameters.
                writer: Output sink that receives one JSON line per captured
                        transaction.

        Returns:
                A :class:`MonitorResult` describing the outcome (``live=False``,
                ``reconnects=0``).

        Raises:
                TimeoutError: A pending GetTransaction request was not answered
                        within ``config.request_timeout`` seconds.
                RuntimeError: The node closed the connection or sent Bye while
                        transactions were still pending.
                OSError: Any underlying socket or TLS error raised by the network or
                        secure channel.
    """
    endpoint = format_address(config.endpoint)
    state = SnapshotState()
    duplicates = 0
    started = time.monotonic()

    connection = BeamConnection(
        host=config.endpoint[0],
        port=config.endpoint[1],
        connect_timeout=config.connect_timeout,
        read_timeout=max(config.request_timeout, config.idle_timeout, 1.0),
        verbose=config.verbose,
    )
    try:
        connection.connect()
        connection.handshake(LOGIN_FLAG_SPREADING_TRANSACTIONS, config.fork_hashes)
        idle_started = time.monotonic()
        request_deadline: float | None = None

        while True:
            next_tx_id = state.begin_request()
            if next_tx_id is not None:
                connection.send(MessageType.GET_TRANSACTION, encode_transaction_id(next_tx_id))
                request_deadline = time.monotonic() + config.request_timeout
                _log(config.verbose, f"[*] {endpoint} requested tx {next_tx_id.hex()}")

            now = time.monotonic()
            if state.in_flight is not None:
                if request_deadline is None:
                    raise RuntimeError("request deadline missing for inflight transaction")
                wait_timeout: float | None = max(request_deadline - now, 0.0)
            elif state.has_pending():
                wait_timeout = 0.0
            else:
                wait_timeout = max(config.idle_timeout - (now - idle_started), 0.0)

            if wait_timeout == 0 and state.is_idle():
                break

            try:
                message_type, payload = connection.recv_message(wait_timeout)
            except socket.timeout:
                now = time.monotonic()
                if (
                    state.in_flight is not None
                    and request_deadline is not None
                    and now >= request_deadline
                ):
                    raise TimeoutError(
                        "timed out waiting for NewTransaction payload for "
                        f"{state.in_flight.hex()}"
                    )
                if state.is_idle() and now - idle_started >= config.idle_timeout:
                    break
                continue
            except ConnectionError:
                if state.is_idle():
                    break
                raise RuntimeError(
                    "connection closed before the mem-pool snapshot completed"
                )

            if message_type == MessageType.HAVE_TRANSACTION:
                try:
                    tx_id = decode_transaction_id(payload)
                except ValueError as exc:
                    _log(config.verbose, f"[*] {endpoint} ignored invalid tx id: {exc}")
                    continue
                if state.observe_announcement(tx_id):
                    idle_started = time.monotonic()
                    _log(config.verbose, f"[*] {endpoint} announced tx {tx_id.hex()}")
                else:
                    duplicates += 1
                    _log(config.verbose, f"[*] {endpoint} duplicate tx {tx_id.hex()}")
                continue

            if message_type == MessageType.NEW_TRANSACTION:
                if state.in_flight is None:
                    _log(config.verbose, f"[*] {endpoint} received unsolicited NewTransaction, ignoring")
                    continue
                tx_id = state.complete_request()
                request_deadline = None
                _write_capture_record(writer, endpoint, config.verbose, tx_id, payload)
                if state.is_idle():
                    idle_started = time.monotonic()
                continue

            if message_type == MessageType.GET_TIME:
                connection.send_time()
                continue

            if message_type == MessageType.PING:
                connection.send(MessageType.PONG)
                continue

            if message_type == MessageType.BYE:
                if state.is_idle():
                    break
                raise RuntimeError("node sent Bye before the mem-pool snapshot completed")

            if message_type in {
                MessageType.TIME,
                MessageType.AUTHENTICATION,
                MessageType.LOGIN,
                MessageType.NEW_TIP,
                MessageType.STATUS,
            }:
                name = message_name(message_type)
                _log(config.verbose, f"[*] {endpoint} <- {name} ({len(payload)}B)")
                continue

            name = message_name(message_type)
            _log(config.verbose, f"[*] {endpoint} ignored {name} ({len(payload)}B)")
    finally:
        connection.close()

    duration = time.monotonic() - started
    return MonitorResult(
        node=endpoint,
        announced=len(state.announced),
        captured=len(state.captured),
        duplicates=duplicates,
        duration_seconds=duration,
        live=False,
        reconnects=0,
    )
