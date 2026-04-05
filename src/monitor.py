"""Transaction monitor for the Beam mempool.

Connects to a Beam node, performs a TLS handshake, and collects every
transaction the node announces via HaveTransaction messages.  For each
announced transaction the monitor sends a GetTransaction request and writes
the retrieved payload to a JsonLineWriter as a CaptureRecord.

Two operating modes are supported:

* **Snapshot mode** (``live=False``): the monitor exits after the node goes
  quiet for ``idle_timeout`` seconds and the pending queue is empty.
* **Live mode** (``live=True``): the monitor runs indefinitely, reconnecting
  automatically on transient errors, and can only be stopped by a
  ``KeyboardInterrupt``.
"""
import socket
import sys
import time
from dataclasses import dataclass, field

from .codec import decode_transaction_id, encode_transaction_id
from .connection import BeamConnection
from .deserializer import deserialize_new_transaction_payload
from .models import CaptureRecord, MonitorResult, SnapshotState
from .protocol import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_RECONNECT_DELAY,
    DEFAULT_REQUEST_TIMEOUT,
    LOGIN_FLAG_SPREADING_TRANSACTIONS,
    MessageType,
    message_name,
    Address,
)
from .storage import JsonLineWriter
from .utils import format_address, utc_now_iso


@dataclass(frozen=True)
class MonitorConfig:
    """Immutable configuration for a single TransactionMonitor instance.

    Attributes:
        endpoint: ``(host, port)`` pair that identifies the Beam node to
            connect to.
        connect_timeout: Maximum time in seconds to wait while establishing
            the TCP connection.
        request_timeout: Maximum time in seconds to wait for a
            NewTransaction payload after sending a GetTransaction request.
            If the deadline is exceeded the monitor raises ``TimeoutError``
            (live mode re-queues the transaction and reconnects instead).
        idle_timeout: In snapshot mode, the monitor considers the mempool
            fully captured and exits after this many seconds of inactivity
            (no new HaveTransaction messages and an empty pending queue).
            Ignored in live mode.
        reconnect_delay: Seconds to sleep between reconnection attempts in
            live mode.  Set to ``0`` to reconnect immediately.
        fork_hashes: List of the raw fork-ID byte strings sent to the node
            during the Login handshake.  Pass an empty list if the node
            requires no specific fork.
        live: ``True`` to run indefinitely, reconnecting on errors.
            ``False`` (default) to take a one-shot mempool snapshot and exit.
        verbose: ``True`` to emit diagnostic log lines to *stderr*.
    """
    endpoint: Address
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT
    reconnect_delay: float = DEFAULT_RECONNECT_DELAY
    fork_hashes: list[bytes] = field(default_factory=list)
    live: bool = False
    verbose: bool = False


def _log(verbose: bool, message: str):
    """Print *message* to *stderr* when *verbose* is ``True``.

    Args:
        verbose: Whether logging is enabled.  Nothing is printed when
            ``False``.
        message: The text to emit.
    """
    if verbose:
        print(message, file=sys.stderr)


class TransactionMonitor:
    """Connects to a Beam node and captures mempool transactions.

    The monitor maintains a ``SnapshotState`` that tracks which transactions
    have been announced, which are still pending retrieval, and which are
    in-flight (i.e. a GetTransaction request has been sent but the
    NewTransaction reply has not yet arrived).  The main loop drives the
    state machine by calling ``SnapshotState.begin_request`` at the top of
    every iteration and dispatching incoming messages accordingly.

    All captured transactions are serialised to the provided
    ``JsonLineWriter`` as ``CaptureRecord`` objects.  When the monitor
    finishes (either because the snapshot is complete or because a
    ``KeyboardInterrupt`` is received) it returns a ``MonitorResult``
    summary.
    """

    def __init__(self, config: MonitorConfig, writer: JsonLineWriter):
        """Initialise the monitor.

        Args:
            config: Immutable settings that control connection behaviour,
                timeouts, and operating mode.
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
        """Emit *message* to *stderr* when verbose logging is enabled.

        Args:
            message: Diagnostic text to print.
        """
        _log(self.config.verbose, message)

    def _next_wait_timeout(
        self,
        request_deadline: float | None,
        idle_started: float,
    ) -> float | None:
        """Compute the receive timeout for the next ``recv_message`` call.

        The returned value is interpreted as follows:

        * **positive float** – block for at most this many seconds.
        * **0.0** – do a non-blocking check (there is work to dispatch
          immediately or the idle deadline has already passed).
        * **None** – block indefinitely (live mode with nothing in-flight
          and an empty pending queue).

        Args:
            request_deadline: Absolute ``time.monotonic()`` timestamp by
                which the in-flight GetTransaction reply must arrive, or
                ``None`` when no request is currently in-flight.
            idle_started: ``time.monotonic()`` timestamp recorded the last
                time the pending queue became empty.  Used to determine how
                much of the idle timeout remains in snapshot mode.

        Returns:
            Seconds to wait, ``0.0`` for a non-blocking poll, or ``None``
            to block indefinitely.

        Raises:
            RuntimeError: When a transaction is in-flight but
                *request_deadline* is ``None``, which indicates a
                programming error.
        """
        now = time.monotonic()
        if self.state.in_flight is not None:
            if request_deadline is None:
                raise RuntimeError("request deadline missing for inflight transaction")
            return max(request_deadline - now, 0.0)

        if self.state.has_pending():
            return 0.0

        if self.config.live:
            return None

        return max(self.config.idle_timeout - (now - idle_started), 0.0)

    def _write_capture_record(
        self,
        tx_id: bytes,
        payload: bytes,
    ):
        """Deserialise *payload* and persist the result as a CaptureRecord.

        Attempts to fully deserialise the raw NewTransaction payload.  If
        deserialisation fails the record is still written with the raw hex
        payload and the exception message stored in ``decode_error``, so no
        data is silently lost.

        Args:
            tx_id: 32-byte transaction identifier.  Used as the record key
                and for diagnostic log messages.
            payload: Raw bytes of the NewTransaction message body as
                received from the node.
        """
        decoded = None
        decode_error = None
        try:
            decoded = deserialize_new_transaction_payload(payload)
        except Exception as exc:
            decode_error = str(exc)
            self._log(
                f"[*] {self.endpoint} failed to decode tx {tx_id.hex()}: {exc}",
            )

        self.writer.write(
            CaptureRecord(
                node=self.endpoint,
                tx_id=tx_id.hex(),
                raw_payload_hex=payload.hex(),
                payload_size=len(payload),
                captured_at=utc_now_iso(),
                decoded=decoded,
                decode_error=decode_error,
            )
        )
        self._log(f"[*] {self.endpoint} captured tx {tx_id.hex()}")

    def _monitor_connection(
        self,
        connection: BeamConnection,
    ) -> bool:
        """Run the capture loop over a single established connection.

        Connects, completes the Login handshake, then processes messages
        from the node in a loop until one of the following conditions is
        met:

        * The pending queue is empty, no request is in-flight, and either
          the idle timeout has elapsed (snapshot mode) or a Bye message was
          received.
        * A ``TimeoutError`` is raised because a GetTransaction reply did
          not arrive within ``request_timeout`` (propagated to the caller).
        * A ``ConnectionError`` or other ``OSError`` is raised (propagated;
          in live mode the caller reconnects).

        Args:
            connection: A freshly created, not-yet-connected ``BeamConnection``
                instance.  This method calls ``connection.connect()`` and
                ``connection.handshake()`` internally.

        Returns:
            ``True`` when the capture session completed normally (the memo
            pool snapshot is considered done).  The caller should not
            reconnect in this case.

        Raises:
            TimeoutError: A pending GetTransaction request was not answered
                within ``config.request_timeout`` seconds.
            ConnectionError: The node closed the connection unexpectedly
                while transactions were still pending.
            RuntimeError: An internal invariant was violated (should not
                happen under normal operation).
        """
        request_deadline: float | None = None
        idle_started = time.monotonic()

        connection.connect()
        connection.handshake(LOGIN_FLAG_SPREADING_TRANSACTIONS, self.config.fork_hashes)
        idle_started = time.monotonic()

        while True:
            next_tx_id = self.state.begin_request()
            if next_tx_id is not None:
                connection.send(MessageType.GET_TRANSACTION, encode_transaction_id(next_tx_id))
                request_deadline = time.monotonic() + self.config.request_timeout
                self._log(f"[*] {self.endpoint} requested tx {next_tx_id.hex()}")

            wait_timeout = self._next_wait_timeout(
                request_deadline,
                idle_started,
            )
            if wait_timeout == 0 and self.state.is_idle():
                return True

            try:
                message_type, payload = connection.recv_message(wait_timeout)
            except socket.timeout:
                now = time.monotonic()
                if self.state.in_flight is not None and request_deadline is not None:
                    if now >= request_deadline:
                        tx_id = self.state.in_flight
                        if self.config.live:
                            self.state.requeue_inflight()
                        raise TimeoutError(
                            "timed out waiting for NewTransaction payload for "
                            f"{tx_id.hex()}"
                        )
                if not self.config.live and self.state.is_idle() and now - idle_started >= self.config.idle_timeout:
                    return True
                continue
            except ConnectionError:
                if self.config.live:
                    self.state.requeue_inflight()
                    raise
                if self.state.is_idle():
                    return True
                raise RuntimeError(
                    "connection closed before the mem-pool snapshot completed"
                )

            if message_type == MessageType.HAVE_TRANSACTION:
                try:
                    tx_id = decode_transaction_id(payload)
                except ValueError as exc:
                    self._log(f"[*] {self.endpoint} ignored invalid tx id: {exc}")
                    continue

                if self.state.observe_announcement(tx_id):
                    idle_started = time.monotonic()
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
                self._write_capture_record(tx_id, payload)
                if self.state.is_idle():
                    idle_started = time.monotonic()
                continue

            if message_type == MessageType.GET_TIME:
                connection.send_time()
                continue

            if message_type == MessageType.PING:
                connection.send(MessageType.PONG)
                continue

            if message_type == MessageType.BYE:
                if self.config.live:
                    self.state.requeue_inflight()
                    raise ConnectionError("node sent Bye")
                if self.state.is_idle():
                    return True
                raise RuntimeError("node sent Bye before the mem-pool snapshot completed")

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
        """Execute the monitor until completion or interruption.

        In snapshot mode (``config.live=False``) the method returns as soon
        as ``_monitor_connection`` signals that the session is complete.
        Any ``OSError`` propagates immediately.

        In live mode (``config.live=True``) the method loops forever,
        reconnecting after transient ``OSError`` failures and pausing
        ``config.reconnect_delay`` seconds between attempts.  The only way
        to stop it is a ``KeyboardInterrupt``.

        Returns:
            A ``MonitorResult`` summarising how many transactions were
            announced, successfully captured, and how many duplicate
            announcements were observed, along with wall-clock duration and
            reconnect count.  ``stopped=True`` when the run was interrupted
            by the user.
        """
        self.started = time.monotonic()

        try:
            while True:
                connection = BeamConnection(
                    host=self.config.endpoint[0],
                    port=self.config.endpoint[1],
                    connect_timeout=self.config.connect_timeout,
                    read_timeout=max(self.config.request_timeout, self.config.idle_timeout, 1.0),
                    verbose=self.config.verbose,
                )
                try:
                    completed = self._monitor_connection(connection)
                    if completed:
                        break
                except OSError as exc:
                    if not self.config.live:
                        raise
                    self.reconnects += 1
                    self._log(
                        (
                            f"[*] {self.endpoint} reconnecting after {exc}; "
                            f"sleeping {self.config.reconnect_delay:g}s"
                        )
                    )
                    if self.config.reconnect_delay > 0:
                        time.sleep(self.config.reconnect_delay)
                finally:
                    connection.close()
        except KeyboardInterrupt:
            duration = time.monotonic() - self.started
            return MonitorResult(
                node=self.endpoint,
                announced=len(self.state.announced),
                captured=len(self.state.captured),
                duplicates=self.duplicates,
                duration_seconds=duration,
                live=self.config.live,
                reconnects=self.reconnects,
                stopped=True,
            )

        duration = time.monotonic() - self.started
        return MonitorResult(
            node=self.endpoint,
            announced=len(self.state.announced),
            captured=len(self.state.captured),
            duplicates=self.duplicates,
            duration_seconds=duration,
            live=self.config.live,
            reconnects=self.reconnects,
        )


def run_transaction_monitor(
    config: MonitorConfig,
    writer: JsonLineWriter,
) -> MonitorResult:
    """Create a ``TransactionMonitor`` and run it to completion.

    Convenience wrapper used by the CLI entry-point so that callers do not
    need to instantiate ``TransactionMonitor`` directly.

    Args:
        config: Connection settings and operating-mode flags for the monitor.
        writer: Output sink that receives one JSON line per captured
            transaction.

    Returns:
        A ``MonitorResult`` describing the outcome of the monitoring session.
    """
    monitor = TransactionMonitor(config, writer)
    return monitor.run()
