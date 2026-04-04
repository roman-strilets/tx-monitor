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
    endpoint: Address
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT
    reconnect_delay: float = DEFAULT_RECONNECT_DELAY
    fork_hashes: list[bytes] = field(default_factory=list)
    live: bool = False
    verbose: bool = False


@dataclass
class MonitorStats:
    duplicates: int = 0


def _log(verbose: bool, message: str):
    if verbose:
        print(message, file=sys.stderr)


def _next_wait_timeout(
    state: SnapshotState,
    request_deadline: float | None,
    idle_started: float,
    idle_timeout: float,
    live: bool,
) -> float | None:
    now = time.monotonic()
    if state.in_flight is not None:
        if request_deadline is None:
            raise RuntimeError("request deadline missing for inflight transaction")
        return max(request_deadline - now, 0.0)

    if state.has_pending():
        return 0.0

    if live:
        return None

    return max(idle_timeout - (now - idle_started), 0.0)


def _write_capture_record(
    config: MonitorConfig,
    writer: JsonLineWriter,
    endpoint: str,
    tx_id: bytes,
    payload: bytes,
):
    decoded = None
    decode_error = None
    try:
        decoded = deserialize_new_transaction_payload(payload)
    except Exception as exc:
        decode_error = str(exc)
        _log(
            config.verbose,
            f"[*] {endpoint} failed to decode tx {tx_id.hex()}: {exc}",
        )

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
    _log(config.verbose, f"[*] {endpoint} captured tx {tx_id.hex()}")


def _monitor_connection(
    config: MonitorConfig,
    writer: JsonLineWriter,
    connection: BeamConnection,
    state: SnapshotState,
    stats: MonitorStats,
) -> bool:
    endpoint = format_address(config.endpoint)
    request_deadline: float | None = None
    idle_started = time.monotonic()

    connection.connect()
    connection.handshake(LOGIN_FLAG_SPREADING_TRANSACTIONS, config.fork_hashes)
    idle_started = time.monotonic()

    while True:
        next_tx_id = state.begin_request()
        if next_tx_id is not None:
            connection.send(MessageType.GET_TRANSACTION, encode_transaction_id(next_tx_id))
            request_deadline = time.monotonic() + config.request_timeout
            _log(config.verbose, f"[*] {endpoint} requested tx {next_tx_id.hex()}")

        wait_timeout = _next_wait_timeout(
            state,
            request_deadline,
            idle_started,
            config.idle_timeout,
            config.live,
        )
        if wait_timeout == 0 and state.is_idle():
            return True

        try:
            message_type, payload = connection.recv_message(wait_timeout)
        except socket.timeout:
            now = time.monotonic()
            if state.in_flight is not None and request_deadline is not None:
                if now >= request_deadline:
                    tx_id = state.in_flight
                    if config.live:
                        state.requeue_inflight()
                    raise TimeoutError(
                        "timed out waiting for NewTransaction payload for "
                        f"{tx_id.hex()}"
                    )
            if not config.live and state.is_idle() and now - idle_started >= config.idle_timeout:
                return True
            continue
        except ConnectionError:
            if config.live:
                state.requeue_inflight()
                raise
            if state.is_idle():
                return True
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
                stats.duplicates += 1
                _log(config.verbose, f"[*] {endpoint} duplicate tx {tx_id.hex()}")
            continue

        if message_type == MessageType.NEW_TRANSACTION:
            if state.in_flight is None:
                _log(config.verbose, f"[*] {endpoint} received unsolicited NewTransaction, ignoring")
                continue
            tx_id = state.complete_request()
            request_deadline = None
            _write_capture_record(config, writer, endpoint, tx_id, payload)
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
            if config.live:
                state.requeue_inflight()
                raise ConnectionError("node sent Bye")
            if state.is_idle():
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
            _log(config.verbose, f"[*] {endpoint} <- {name} ({len(payload)}B)")
            continue

        name = message_name(message_type)
        _log(config.verbose, f"[*] {endpoint} ignored {name} ({len(payload)}B)")


def run_transaction_monitor(
    config: MonitorConfig,
    writer: JsonLineWriter,
) -> MonitorResult:
    endpoint = format_address(config.endpoint)
    state = SnapshotState()
    stats = MonitorStats()
    reconnects = 0
    started = time.monotonic()

    try:
        while True:
            connection = BeamConnection(
                host=config.endpoint[0],
                port=config.endpoint[1],
                connect_timeout=config.connect_timeout,
                read_timeout=max(config.request_timeout, config.idle_timeout, 1.0),
                verbose=config.verbose,
            )
            try:
                completed = _monitor_connection(
                    config,
                    writer,
                    connection,
                    state,
                    stats,
                )
                if completed:
                    break
            except OSError as exc:
                if not config.live:
                    raise
                reconnects += 1
                _log(
                    config.verbose,
                    (
                        f"[*] {endpoint} reconnecting after {exc}; "
                        f"sleeping {config.reconnect_delay:g}s"
                    ),
                )
                if config.reconnect_delay > 0:
                    time.sleep(config.reconnect_delay)
            finally:
                connection.close()
    except KeyboardInterrupt:
        duration = time.monotonic() - started
        return MonitorResult(
            node=endpoint,
            announced=len(state.announced),
            captured=len(state.captured),
            duplicates=stats.duplicates,
            duration_seconds=duration,
            live=config.live,
            reconnects=reconnects,
            stopped=True,
        )

    duration = time.monotonic() - started
    return MonitorResult(
        node=endpoint,
        announced=len(state.announced),
        captured=len(state.captured),
        duplicates=stats.duplicates,
        duration_seconds=duration,
        live=config.live,
        reconnects=reconnects,
    )


def capture_mempool_snapshot(
    config: MonitorConfig,
    writer: JsonLineWriter,
) -> MonitorResult:
    if config.live:
        raise ValueError("capture_mempool_snapshot does not support live mode")
    return run_transaction_monitor(config, writer)