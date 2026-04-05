import unittest
from unittest.mock import MagicMock

from src.codec import decode_uint
from src.connection import build_login_payload
from src.models import SnapshotState
from src.monitor import MonitorConfig, TransactionMonitor
from src.protocol import EXTENSION_VERSION, LOGIN_FLAG_SPREADING_TRANSACTIONS
from src.utils import extension_bits


class MonitorTests(unittest.TestCase):
    def test_build_login_payload_sets_flags_and_fork_hashes(self):
        fork_hashes = [b"\x11" * 32, b"\x22" * 32]
        payload = build_login_payload(LOGIN_FLAG_SPREADING_TRANSACTIONS, fork_hashes)

        count, size = decode_uint(payload)
        self.assertEqual(count, 2)

        offset = size
        self.assertEqual(payload[offset : offset + 32], fork_hashes[0])
        offset += 32
        self.assertEqual(payload[offset : offset + 32], fork_hashes[1])
        offset += 32

        flags, size = decode_uint(payload, offset)
        self.assertEqual(
            flags,
            LOGIN_FLAG_SPREADING_TRANSACTIONS
            | (extension_bits(EXTENSION_VERSION) << 4),
        )
        self.assertEqual(offset + size, len(payload))

    def test_snapshot_state_deduplicates_announcements(self):
        state = SnapshotState()
        tx_id = b"\x01" * 32

        self.assertTrue(state.observe_announcement(tx_id))
        self.assertFalse(state.observe_announcement(tx_id))
        self.assertEqual(list(state.pending), [tx_id])

    def test_snapshot_state_sequences_requests(self):
        state = SnapshotState()
        first = b"\x01" * 32
        second = b"\x02" * 32

        state.observe_announcement(first)
        state.observe_announcement(second)

        self.assertEqual(state.begin_request(), first)
        self.assertIsNone(state.begin_request())
        self.assertEqual(state.complete_request(), first)
        self.assertEqual(state.begin_request(), second)
        self.assertEqual(state.complete_request(), second)
        self.assertTrue(state.is_idle())
        self.assertEqual(state.captured, {first, second})

    def test_complete_request_requires_inflight_state(self):
        with self.assertRaises(RuntimeError):
            SnapshotState().complete_request()

    def test_requeue_inflight_returns_request_to_pending(self):
        state = SnapshotState()
        tx_id = b"\x03" * 32

        state.observe_announcement(tx_id)
        self.assertEqual(state.begin_request(), tx_id)

        state.requeue_inflight()

        self.assertIsNone(state.in_flight)
        self.assertEqual(list(state.pending), [tx_id])

    def test_live_wait_timeout_blocks_while_idle(self):
        config = MonitorConfig(endpoint=("1.2.3.4", 8100), idle_timeout=3.0, live=True)
        monitor = TransactionMonitor(config, MagicMock())

        wait_timeout = monitor._next_wait_timeout(
            request_deadline=None,
            idle_started=0.0,
        )

        self.assertIsNone(wait_timeout)


if __name__ == "__main__":
    unittest.main()