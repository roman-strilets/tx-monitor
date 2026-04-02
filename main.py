import argparse
import sys

from src.monitor import MonitorConfig, run_transaction_monitor
from src.protocol import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PORT,
    DEFAULT_RECONNECT_DELAY,
    DEFAULT_REQUEST_TIMEOUT,
)
from src.storage import JsonLineWriter
from src.utils import parse_endpoint, parse_fork_hashes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture or live-monitor Beam mem-pool transactions from a node"
    )
    parser.add_argument("node", help="Beam node address as host or host:port")
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help=(
            "TCP connect and handshake timeout in seconds "
            f"(default {DEFAULT_CONNECT_TIMEOUT:g})"
        ),
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=DEFAULT_REQUEST_TIMEOUT,
        help=(
            "seconds to wait for each requested transaction payload "
            f"(default {DEFAULT_REQUEST_TIMEOUT:g})"
        ),
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=DEFAULT_IDLE_TIMEOUT,
        help=(
            "seconds of silence after the queue is empty before snapshot mode ends "
            f"(default {DEFAULT_IDLE_TIMEOUT:g})"
        ),
    )
    parser.add_argument(
        "--live",
        "--follow",
        dest="live",
        action="store_true",
        help="stay connected and keep streaming new transactions after the initial queue",
    )
    parser.add_argument(
        "--reconnect-delay",
        type=float,
        default=DEFAULT_RECONNECT_DELAY,
        help=(
            "seconds to wait before reconnecting in live mode after a disconnect "
            f"(default {DEFAULT_RECONNECT_DELAY:g})"
        ),
    )
    parser.add_argument(
        "--fork-hash",
        action="append",
        default=[],
        metavar="HEX",
        help="fork config hash (64 hex chars); repeat per fork",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="write JSON lines to this file instead of stdout",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print handshake and message-level diagnostics to stderr",
    )
    args = parser.parse_args(argv)

    for label, value in (
        ("connect-timeout", args.connect_timeout),
        ("request-timeout", args.request_timeout),
        ("idle-timeout", args.idle_timeout),
    ):
        if value <= 0:
            parser.error(f"{label} must be > 0")
    if args.reconnect_delay < 0:
        parser.error("reconnect-delay must be >= 0")

    try:
        endpoint = parse_endpoint(args.node, DEFAULT_PORT)
        fork_hashes = parse_fork_hashes(args.fork_hash)

        config = MonitorConfig(
            endpoint=endpoint,
            connect_timeout=args.connect_timeout,
            request_timeout=args.request_timeout,
            idle_timeout=args.idle_timeout,
            reconnect_delay=args.reconnect_delay,
            fork_hashes=fork_hashes,
            live=args.live,
            verbose=args.verbose,
        )

        with JsonLineWriter(args.output) as writer:
            result = run_transaction_monitor(config, writer)

        if result.live:
            status = "stopped" if result.stopped else "ended"
            print(
                f"{status} live monitor for {result.node}; "
                f"captured={result.captured}, announced={result.announced}, "
                f"duplicates={result.duplicates}, reconnects={result.reconnects}, "
                f"elapsed={result.duration_seconds:.2f}s",
                file=sys.stderr,
            )
        else:
            print(
                "captured "
                f"{result.captured} transaction(s) from {result.node}; "
                f"announced={result.announced}, duplicates={result.duplicates}, "
                f"elapsed={result.duration_seconds:.2f}s",
                file=sys.stderr,
            )
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
