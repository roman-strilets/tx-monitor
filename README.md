# tx-monitor

tx-monitor captures Beam mem-pool transactions from a node using the native Beam
P2P protocol.

It connects to the node over the secure channel, logs in with the
SpreadingTransactions flag, receives HaveTransaction announcements, requests each
transaction with GetTransaction, and stores the raw NewTransaction payloads.

By default it takes a one-shot snapshot. With `--live`, it keeps the connection
open after the initial queue drains and continues streaming newly announced
transactions.

## Usage

```bash
python main.py 127.0.0.1:10000 --idle-timeout 3 --output mempool.jsonl
```

Live monitoring:

```bash
python main.py 127.0.0.1:10000 --live --output mempool-live.jsonl
```

Optional flags:

- `--connect-timeout` controls TCP connect and handshake timeout.
- `--request-timeout` controls how long tx-monitor waits for each requested
	transaction payload.
- `--idle-timeout` controls when the snapshot finishes after the queue becomes
	empty. It is ignored in live mode.
- `--live` keeps streaming new transactions after the initial mem-pool queue.
- `--reconnect-delay` controls how long live mode waits before reconnecting after
	a disconnect.
- `--fork-hash` can be repeated to send explicit Beam fork hashes during Login.
- `-v` prints protocol diagnostics to stderr.

## Output

The default output format is JSON lines. Each line contains:

- `node`: node endpoint used for the capture
- `tx_id`: announced transaction ID in hex
- `raw_payload_hex`: raw `NewTransaction` payload in hex
- `payload_size`: payload size in bytes
- `captured_at`: UTC timestamp in ISO 8601 format
- `decoded`: structured deserialization of the Beam `NewTransaction` payload when parsing succeeds
- `decode_error`: parser error text when raw capture succeeds but structured decoding fails

When `--output` is omitted, JSON lines are written to stdout and the human
summary is written to stderr.

## Limits

- This captures the node's externally gossiped fluffed mem-pool path.
- It does not expose internal stem or dependent transaction states.
- It keeps the raw payload and also emits a structured decode of the transaction.
- Snapshot completion is based on an idle timeout because the Beam peer protocol
	does not emit an explicit end-of-mempool marker.
- Live mode keeps a set of captured transaction IDs in memory to avoid writing
	duplicate records after reconnects or repeated announcements.

## Tests

```bash
python -m unittest discover -s tests
```
