from collections import deque
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CaptureRecord:
    node: str
    tx_id: str
    raw_payload_hex: str
    payload_size: int
    captured_at: str
    decoded: dict[str, object] | None = None
    decode_error: str | None = None

    def as_dict(self) -> dict[str, object]:
        record: dict[str, object] = {
            "node": self.node,
            "tx_id": self.tx_id,
            "raw_payload_hex": self.raw_payload_hex,
            "payload_size": self.payload_size,
            "captured_at": self.captured_at,
        }
        if self.decoded is not None:
            record["decoded"] = self.decoded
        if self.decode_error is not None:
            record["decode_error"] = self.decode_error
        return record


@dataclass(frozen=True)
class MonitorResult:
    node: str
    announced: int
    captured: int
    duplicates: int
    duration_seconds: float
    live: bool = False
    reconnects: int = 0
    stopped: bool = False


@dataclass
class SnapshotState:
    pending: deque[bytes] = field(default_factory=deque)
    announced: set[bytes] = field(default_factory=set)
    captured: set[bytes] = field(default_factory=set)
    in_flight: bytes | None = None

    def observe_announcement(self, tx_id: bytes) -> bool:
        if tx_id in self.announced:
            return False

        self.announced.add(tx_id)
        if tx_id not in self.captured:
            self.pending.append(tx_id)
        return True

    def begin_request(self) -> bytes | None:
        if self.in_flight is not None or not self.pending:
            return None

        self.in_flight = self.pending.popleft()
        return self.in_flight

    def complete_request(self) -> bytes:
        if self.in_flight is None:
            raise RuntimeError("no transaction request is in flight")

        tx_id = self.in_flight
        self.captured.add(tx_id)
        self.in_flight = None
        return tx_id

    def requeue_inflight(self):
        if self.in_flight is None:
            return

        self.pending.appendleft(self.in_flight)
        self.in_flight = None

    def has_pending(self) -> bool:
        return bool(self.pending)

    def is_idle(self) -> bool:
        return self.in_flight is None and not self.pending