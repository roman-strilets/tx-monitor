"""Persistent live transaction monitor for the Beam mempool.

Connects to a Beam node, performs a TLS handshake, and streams every
transaction the node announces via HaveTransaction messages indefinitely.
Reconnects automatically on transient errors.  The only way to stop it is
a ``KeyboardInterrupt``.

For a one-shot mempool snapshot see :mod:`src.snapshot`.
"""
import socket
import sys
import time
from dataclasses import dataclass, field

from src.codec import decode_transaction_id, encode_transaction_id
from src.connection import BeamConnection
from src.deserializers import deserialize_new_transaction_payload
from src.models import CaptureRecord, MonitorResult, SnapshotState
from src.protocol import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_RECONNECT_DELAY,
    DEFAULT_REQUEST_TIMEOUT,
    LOGIN_FLAG_SPREADING_TRANSACTIONS,
    MessageType,
    message_name,
    Address,
)
from src.storage import JsonLineWriter
from src.utils import format_address, utc_now_iso


@dataclass(frozen=True)
class LiveConfig:
    """Immutable configuration for a persistent live monitor.

    Attributes:
        endpoint: ``(host, port)`` pair identifying the Beam node.
        connect_timeout: Maximum time in seconds to wait while establishing
            the TCP connection.
        request_timeout: Maximum time in seconds to wait for a
            NewTransaction payload after sending a GetTransaction request.
            When the deadline is exceeded the in-flight transaction is
            re-queued and the monitor reconnects.
        reconnect_delay: Seconds to sleep between reconnection attempts.
            Set to ``0`` to reconnect immediately.
        fork_hashes: List of raw fork-ID byte strings sent to the node
            during the Login handshake.  Pass an empty list if the node
            requires no specific fork.
        verbose: ``True`` to emit diagnostic log lines to *stderr*.
    """

    endpoint: Address
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    reconnect_delay: float = DEFAULT_RECONNECT_DELAY
    fork_hashes: list[bytes] = field(default_factory=list)
    verbose: bool = False


def _log(verbose: bool, message: str) -> None:
    """Print a diagnostic message to stderr when `verbose` is true.

    This small helper centralises conditional verbose logging so callers
    don't need to check the `verbose` flag themselves.

    Args:
        verbose: If True, the message is printed to `sys.stderr`.
        message: The text to print.
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
    """Decode a NewTransaction payload and persist a CaptureRecord.

    Attempts to decode the raw `payload` using
    :func:`src.deserializers.deserialize_new_transaction_payload`. Any
    decoding error is captured in the ``decode_error`` field of the written
    record and logged when ``verbose`` is True.

    The function writes a :class:`src.models.CaptureRecord` to ``writer``
    containing the following fields: ``node`` (endpoint), ``tx_id`` (hex),
    ``raw_payload_hex``, ``payload_size``, ``captured_at`` (ISO timestamp),
    ``decoded`` (decoded payload or ``None``) and ``decode_error`` (error
    message or ``None``).

    Args:
        writer: ``JsonLineWriter`` used to persist the record.
        endpoint: Formatted node address string.
        verbose: If True, emit diagnostic log lines.
        tx_id: Raw transaction id bytes (will be hex-encoded).
        payload: Raw NewTransaction payload bytes.

    Side effects:
        Calls ``writer.write(...)`` and may call :func:`_log`. Exceptions
        raised by ``writer.write`` are propagated to the caller.
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


class TransactionMonitor:
    """Connects to a Beam node and streams mempool transactions indefinitely.

    Maintains a ``SnapshotState`` tracking announced, pending, and in-flight
    transactions.  Reconnects automatically after transient errors.  The only
    way to stop the monitor is a ``KeyboardInterrupt``.
    """

    def __init__(self, config: LiveConfig, writer: JsonLineWriter):
        """Initialise the monitor.

        Args:
            config: Immutable settings that control connection behaviour and
                timeouts.
            writer: Output sink that receives one ``CaptureRecord`` JSON line
                per successfully retrieved transaction.
        """
        self.config = config
        self.writer = writer
        self.endpoint = format_address(config.endpoint)
        self.state = SnapshotState()
        self.duplicates = 0
        self.started = 0.0
        self.reconnects = 0

    def _log(self, message: str):
        """Log a message using the monitor's configured verbosity.

        Wrapper around module-level ``_log`` that uses ``self.config.verbose``
        so instance methods can simply call ``self._log(message)``.

        Args:
            message: The message to emit when verbosity is enabled.
        """
        _log(self.config.verbose, message)

    def _next_wait_timeout(
        self,
        request_deadline: float | None,
    ) -> float | None:
        """Compute the receive timeout for the next ``recv_message`` call.

        Returns:
            Positive float to block until the request deadline, ``0.0`` for a
            non-blocking poll when there is pending work, or ``None`` to block
            indefinitely when the queue is empty.

        Raises:
            RuntimeError: When a transaction is in-flight but
                *request_deadline* is ``None``.
        """
        now = time.monotonic()
        if self.state.in_flight is not None:
            if request_deadline is None:
                raise RuntimeError("request deadline missing for inflight transaction")
            return max(request_deadline - now, 0.0)

        if self.state.has_pending():
            return 0.0

        return None  # Idle: block indefinitely waiting for new announcements.

    def _monitor_connection(
        self,
        connection: BeamConnection,
    ) -> None:
        """Run the capture loop over a single established connection.

        Connects, completes the Login handshake, then processes messages
        until a ``TimeoutError``, ``ConnectionError``, or other ``OSError``
        terminates the session.  The caller catches these and reconnects.

        Args:
            connection: A freshly created, not-yet-connected ``BeamConnection``.

        Raises:
            TimeoutError: A GetTransaction reply did not arrive within
                ``config.request_timeout`` seconds.  The in-flight transaction
                is re-queued before raising.
            ConnectionError: The node closed the connection or sent Bye.
                The in-flight transaction is re-queued before raising.
        """
        request_deadline: float | None = None

        connection.connect()
        connection.handshake(LOGIN_FLAG_SPREADING_TRANSACTIONS, self.config.fork_hashes)

        while True:
            next_tx_id = self.state.begin_request()
            if next_tx_id is not None:
                connection.send(MessageType.GET_TRANSACTION, encode_transaction_id(next_tx_id))
                request_deadline = time.monotonic() + self.config.request_timeout
                self._log(f"[*] {self.endpoint} requested tx {next_tx_id.hex()}")

            wait_timeout = self._next_wait_timeout(request_deadline)

            try:
                message_type, payload = connection.recv_message(wait_timeout)
            except socket.timeout:
                if (
                    self.state.in_flight is not None
                    and request_deadline is not None
                    and time.monotonic() >= request_deadline
                ):
                    tx_id = self.state.in_flight
                    self.state.requeue_inflight()
                    raise TimeoutError(
                        "timed out waiting for NewTransaction payload for "
                        f"{tx_id.hex()}"
                    )
                continue
            except ConnectionError:
                self.state.requeue_inflight()
                raise

            if message_type == MessageType.HAVE_TRANSACTION:
                try:
                    tx_id = decode_transaction_id(payload)
                except ValueError as exc:
                    self._log(f"[*] {self.endpoint} ignored invalid tx id: {exc}")
                    continue
                if self.state.observe_announcement(tx_id):
                    self._log(f"[*] {self.endpoint} announced tx {tx_id.hex()}")
                else:
                    self.duplicates += 1
                    self._log(f"[*] {self.endpoint} duplicate tx {tx_id.hex()}")
                continue

            if message_type == MessageType.NEW_TRANSACTION:
                if self.state.in_flight is None:
                    self._log(f"[*] {self.endpoint} received unsolicited NewTransaction, ignoring")
                    continue
                tx_id = self.state.complete_request()
                request_deadline = None
                _write_capture_record(self.writer, self.endpoint, self.config.verbose, tx_id, payload)
                continue

            if message_type == MessageType.GET_TIME:
                connection.send_time()
                continue

            if message_type == MessageType.PING:
                connection.send(MessageType.PONG)
                continue

            if message_type == MessageType.BYE:
                self.state.requeue_inflight()
                raise ConnectionError("node sent Bye")

            if message_type in {
                MessageType.TIME,
                MessageType.AUTHENTICATION,
                MessageType.LOGIN,
                MessageType.NEW_TIP,
                MessageType.STATUS,
            }:
                name = message_name(message_type)
                self._log(f"[*] {self.endpoint} <- {name} ({len(payload)}B)")
                continue

            name = message_name(message_type)
            self._log(f"[*] {self.endpoint} ignored {name} ({len(payload)}B)")

    def run(self) -> MonitorResult:
        """Stream transactions indefinitely until interrupted.

        Loops forever, reconnecting after transient ``OSError`` failures and
        sleeping ``config.reconnect_delay`` seconds between attempts.  The
        only way to stop the monitor is a ``KeyboardInterrupt``.

        Returns:
            A ``MonitorResult`` with ``live=True`` and ``stopped=True``.
        """
        self.started = time.monotonic()

        try:
            while True:
                connection = BeamConnection(
                    host=self.config.endpoint[0],
                    port=self.config.endpoint[1],
                    connect_timeout=self.config.connect_timeout,
                    read_timeout=max(self.config.request_timeout, 1.0),
                    verbose=self.config.verbose,
                )
                try:
                    self._monitor_connection(connection)
                except OSError as exc:
                    self.reconnects += 1
                    self._log(
                        f"[*] {self.endpoint} reconnecting after {exc}; "
                        f"sleeping {self.config.reconnect_delay:g}s"
                    )
                    if self.config.reconnect_delay > 0:
                        time.sleep(self.config.reconnect_delay)
                finally:
                    connection.close()
        except KeyboardInterrupt:
            pass

        duration = time.monotonic() - self.started
        return MonitorResult(
            node=self.endpoint,
            announced=len(self.state.announced),
            captured=len(self.state.captured),
            duplicates=self.duplicates,
            duration_seconds=duration,
            live=True,
            reconnects=self.reconnects,
            stopped=True,
        )


def run_transaction_monitor(
    config: LiveConfig,
    writer: JsonLineWriter,
) -> MonitorResult:
    """Create a ``TransactionMonitor`` and run it until interrupted.

    Args:
        config: Connection settings for the live monitor.
        writer: Output sink that receives one JSON line per captured
            transaction.

    Returns:
        A ``MonitorResult`` describing the outcome of the monitoring session.
    """
    monitor = TransactionMonitor(config, writer)
    return monitor.run()
