"""Data models used by the Beam transaction monitor and block fetcher.

Contains frozen dataclasses for the output record (:class:`CaptureRecord`)
and the monitoring summary (:class:`MonitorResult`), block-fetch record and
result types, and the mutable :class:`SnapshotState` that tracks pending and
in-flight transaction requests during a capture session.
"""
from collections import deque
from dataclasses import asdict, dataclass, field

from src.protocol_models import DecodedBlock, NewTransactionPayload


@dataclass(frozen=True)
class CaptureRecord:
    """Immutable record of a single captured mem-pool transaction.

    Written as one JSON line per transaction to the configured output sink.
    """
    node: str
    tx_id: str
    raw_payload_hex: str
    payload_size: int
    captured_at: str
    decoded: NewTransactionPayload | None = None
    decode_error: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable dictionary representation of this record.

        Optional fields (``decoded``, ``decode_error``) are omitted when
        ``None`` to keep the output compact.
        """
        record: dict[str, object] = {
            "node": self.node,
            "tx_id": self.tx_id,
            "raw_payload_hex": self.raw_payload_hex,
            "payload_size": self.payload_size,
            "captured_at": self.captured_at,
        }
        if self.decoded is not None:
            record["decoded"] = asdict(self.decoded)
        if self.decode_error is not None:
            record["decode_error"] = self.decode_error
        return record


@dataclass(frozen=True)
class BlockCaptureRecord:
    """Immutable record of a single fetched Beam block."""

    node: str
    requested_height: int
    resolved_height: int | None
    resolved_hash: str | None
    captured_at: str
    decoded: DecodedBlock | None = None
    decode_error: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable dictionary representation of this record."""
        record: dict[str, object] = {
            "node": self.node,
            "requested_height": self.requested_height,
            "captured_at": self.captured_at,
        }
        if self.resolved_height is not None:
            record["resolved_height"] = self.resolved_height
        if self.resolved_hash is not None:
            record["resolved_hash"] = self.resolved_hash
        if self.decoded is not None:
            record["decoded"] = asdict(self.decoded)
        if self.decode_error is not None:
            record["decode_error"] = self.decode_error
        return record


@dataclass(frozen=True)
class MonitorResult:
    """Summary returned by :meth:`~src.monitor.TransactionMonitor.run`.

    Reports how many transactions were announced by the node, how many were
    successfully captured, how many announcements were duplicates, the total
    wall-clock duration, and (in live mode) how many reconnects occurred.
    """
    node: str
    announced: int
    captured: int
    duplicates: int
    duration_seconds: float
    live: bool = False
    reconnects: int = 0
    stopped: bool = False


@dataclass(frozen=True)
class BlockFetchResult:
    """Summary returned by the one-shot block fetch flow."""

    node: str
    requested_height: int
    resolved_height: int
    resolved_hash: str
    inputs: int
    outputs: int
    kernels: int
    duration_seconds: float


JsonLineRecord = CaptureRecord | BlockCaptureRecord


@dataclass
class SnapshotState:
    """Mutable state for one mem-pool capture session.

    Tracks which transaction IDs have been announced, which are waiting to be
    fetched (``pending``), and which fetch is currently in-flight.  All
    methods that mutate state return useful values so callers can react
    immediately without additional attribute reads.
    """
    pending: deque[bytes] = field(default_factory=deque)
    announced: set[bytes] = field(default_factory=set)
    captured: set[bytes] = field(default_factory=set)
    in_flight: bytes | None = None

    def observe_announcement(self, tx_id: bytes) -> bool:
        """Record a newly announced transaction ID.

        If *tx_id* has already been seen this call is a no-op and returns
        ``False`` (duplicate).  Otherwise the ID is added to ``announced``
        and, if not already captured, enqueued in ``pending``.

        Args:
            tx_id: 32-byte transaction identifier.

        Returns:
            ``True`` if this is the first time the ID was seen, ``False`` if
            it is a duplicate.
        """
        if tx_id in self.announced:
            return False

        self.announced.add(tx_id)
        if tx_id not in self.captured:
            self.pending.append(tx_id)
        return True

    def begin_request(self) -> bytes | None:
        """Dequeue the next pending transaction and mark it as in-flight.

        Returns
            ``None`` when a request is already in-flight or the queue is
            empty; otherwise the 32-byte ID of the newly in-flight
            transaction.
        """
        if self.in_flight is not None or not self.pending:
            return None

        self.in_flight = self.pending.popleft()
        return self.in_flight

    def complete_request(self) -> bytes:
        """Mark the in-flight request as successfully captured.

        Returns:
            The 32-byte ID of the newly captured transaction.

        Raises:
            RuntimeError: If no request is currently in-flight.
        """
        if self.in_flight is None:
            raise RuntimeError("no transaction request is in flight")

        tx_id = self.in_flight
        self.captured.add(tx_id)
        self.in_flight = None
        return tx_id

    def requeue_inflight(self):
        """Return the in-flight transaction to the front of the pending queue.

        Called when a connection error interrupts an in-flight request so
        that the transaction can be retried on reconnect.  Does nothing when
        no request is in-flight.
        """
        if self.in_flight is None:
            return

        self.pending.appendleft(self.in_flight)
        self.in_flight = None

    def has_pending(self) -> bool:
        """Return ``True`` when there are transactions waiting to be fetched."""
        return bool(self.pending)

    def is_idle(self) -> bool:
        """Return ``True`` when no request is in-flight and the queue is empty."""
        return self.in_flight is None and not self.pending