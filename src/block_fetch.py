"""One-shot Beam block fetch over the native peer-to-peer protocol."""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field

from beam_p2p import (
    Address,
    BeamConnection,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_REQUEST_TIMEOUT,
    MessageType,
    encode_get_body_pack_payload,
    encode_height_range,
    format_address,
    message_name,
    utc_now_iso,
)
from beam_p2p.deserializers import (
    deserialize_body_pack_payload,
    deserialize_body_payload,
    deserialize_header_pack,
    deserialize_new_tip_payload,
)
from src.models import BlockCaptureRecord, BlockFetchResult
from src.storage import JsonLineWriter


BODY_FLAG_FULL = 0
DEFAULT_MAX_ROLLBACK = 1440


@dataclass(frozen=True)
class BlockFetchConfig:
    """Immutable configuration for a one-shot block fetch."""

    endpoint: Address
    height: int
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    fork_hashes: list[bytes] = field(default_factory=list)
    verbose: bool = False


def _log(verbose: bool, message: str) -> None:
    """Log a message to standard error when verbose mode is enabled.

    This small helper centralizes conditional debug printing so callers can
    uniformly check the verbose flag before emitting diagnostic output.

    Args:
        verbose: If True, the message will be printed to stderr.
        message: The text message to print.

    Returns:
        None.
    """
    if verbose:
        print(message, file=sys.stderr)


def _recv_until(
    connection: BeamConnection,
    *,
    endpoint: str,
    expected: set[MessageType],
    timeout: float,
) -> tuple[MessageType, bytes]:
    """Receive messages until one of the expected message types is returned.

    The function repeatedly calls `connection.recv_message(timeout)` and
    handles control frames from the peer according to the Beam protocol. It
    will respond to a small set of control messages automatically and either
    return when an expected message is received or raise on terminal errors.

    Behavior summary:
      - If `GET_TIME` is received, `connection.send_time()` is called and loop continues.
      - If `PING` is received, replies with `MessageType.PONG` and continues.
      - If `BYE` is received, raises `RuntimeError` (peer closed connection).
      - If `DATA_MISSING` is received, raises `RuntimeError` (requested block
        data is unavailable from the peer).
      - Message types considered informational (e.g. `TIME`, `AUTHENTICATION`,
        `LOGIN`, `NEW_TIP`, `STATUS`) are logged (when `connection.verbose`) and ignored.
      - Any other message types are logged and ignored.

    Args:
        connection: Active `BeamConnection` instance used to receive/send
            protocol messages. The function calls `recv_message(timeout)` and may
            call `send_time()` or `send()` on this object.
        endpoint: Human-readable address string used for log messages (for
            example, "host:port").
        expected: Set of `MessageType` values that the caller is waiting for.
            When a message whose type is in this set is received, the function
            returns that `(message_type, payload)` tuple.
        timeout: Read timeout in seconds passed to `connection.recv_message`.

    Returns:
        A tuple `(message_type, payload)` where `message_type` is a member of
        `expected` and `payload` is the raw bytes payload for that message.

    Raises:
        RuntimeError: If the peer sends `BYE` or `DATA_MISSING`, indicating an
            unrecoverable condition for the requested fetch.
    """
    while True:
        message_type, payload = connection.recv_message(timeout)

        if message_type in expected:
            return message_type, payload

        if message_type == MessageType.GET_TIME:
            connection.send_time()
            continue

        if message_type == MessageType.PING:
            connection.send(MessageType.PONG)
            continue

        if message_type == MessageType.BYE:
            raise RuntimeError("node sent Bye before the block fetch completed")

        if message_type == MessageType.DATA_MISSING:
            raise RuntimeError("node reported the requested block data is missing")

        if message_type in {
            MessageType.TIME,
            MessageType.AUTHENTICATION,
            MessageType.LOGIN,
            MessageType.NEW_TIP,
            MessageType.STATUS,
        }:
            _log(
                connection.verbose,
                f"[*] {endpoint} <- {message_name(message_type)} ({len(payload)}B)",
            )
            continue

        _log(
            connection.verbose,
            f"[*] {endpoint} ignored {message_name(message_type)} ({len(payload)}B)",
        )


def _wait_for_tip_header(connection: BeamConnection, endpoint: str, timeout: float):
    """Block until a `NEW_TIP` message is received and return the deserialized tip.

    This wraps `_recv_until` to wait specifically for the peer's advertised
    chain tip. The returned object is produced by
    `deserialize_new_tip_payload` and typically contains attributes such as
    `height` and `hash` describing the current tip.

    Args:
        connection: Active `BeamConnection` used to read the `NEW_TIP` message.
        endpoint: Human-readable address string for logging.
        timeout: Read timeout in seconds to wait for the tip message.

    Returns:
        The deserialized tip header object from `deserialize_new_tip_payload`.

    Raises:
        RuntimeError: If a non-`NEW_TIP` message is returned by `_recv_until`.
    """
    message_type, payload = _recv_until(
        connection,
        endpoint=endpoint,
        expected={MessageType.NEW_TIP},
        timeout=timeout,
    )
    if message_type != MessageType.NEW_TIP:
        raise RuntimeError(f"expected NewTip, got {message_name(message_type)}")
    return deserialize_new_tip_payload(payload, connection.peer_fork_hashes)


def _request_header(
    connection: BeamConnection,
    *,
    endpoint: str,
    height: int,
    timeout: float,
):
    """Request the header for a single block height and return the deserialized pack.

    Sends an `ENUM_HDRS` request constrained to the single `height` and waits for a
    `HDR_PACK` response. The response payload is deserialized with
    `deserialize_header_pack` using the peer's fork hashes.

    Args:
        connection: Active `BeamConnection` used to send the request and receive the reply.
        endpoint: Human-readable address string used for debug logging.
        height: The block height to request.
        timeout: Read timeout in seconds for the header reply.

    Returns:
        The deserialized header pack for the requested height.

    Raises:
        RuntimeError: If a non-`HDR_PACK` message is returned while waiting for the header.
    """
    connection.send(MessageType.ENUM_HDRS, encode_height_range(height, height))
    _log(connection.verbose, f"[*] {endpoint} requested header for height {height}")

    message_type, payload = _recv_until(
        connection,
        endpoint=endpoint,
        expected={MessageType.HDR_PACK},
        timeout=timeout,
    )
    if message_type != MessageType.HDR_PACK:
        raise RuntimeError(f"expected HdrPack, got {message_name(message_type)}")
    return deserialize_header_pack(payload, connection.peer_fork_hashes)


def _request_body(
    connection: BeamConnection,
    *,
    endpoint: str,
    target_header,
    tip_header,
    timeout: float,
):
    """Request and decode the block body corresponding to `target_header`.

    The function decides whether to request a single `BODY` (when the target is the
    current tip) or a `BODY_PACK` (when the target is below tip and extra
    blocks may be returned for rollback handling). The deserialized block is
    returned as the result of the appropriate deserializer.

    Args:
        connection: Active `BeamConnection` used for the request/response exchange.
        endpoint: Human-readable address string for debug logging.
        target_header: Header object for the block being requested (must expose
            `.height` and `.hash`). This is typically the header returned by
            `_request_header` for the desired height.
        tip_header: Header object representing the peer's current tip (must expose
            `.height` and `.hash`) used to compute whether the target is at tip.
        timeout: Read timeout in seconds passed to `connection.recv_message`.

    Returns:
        A decoded block object produced by `deserialize_body_payload` or
        `deserialize_body_pack_payload`. The object normally contains a
        `.header` with `height`/`hash` and a `.counts` structure used by callers.

    Raises:
        RuntimeError: If the requested height is above the peer's tip, or if an
            unexpected message type is received while waiting for the body.
    """
    count_extra = tip_header.height - target_header.height
    if count_extra < 0:
        raise RuntimeError(
            f"requested height {target_header.height} is above current tip {tip_header.height}"
        )

    if count_extra == 0:
        payload = encode_get_body_pack_payload(
            top_height=tip_header.height,
            top_hash=bytes.fromhex(tip_header.hash),
            flag_perishable=BODY_FLAG_FULL,
            flag_eternal=BODY_FLAG_FULL,
            count_extra=0,
            block0=0,
            horizon_lo1=0,
            horizon_hi1=0,
        )
        expected = {MessageType.BODY}
    else:
        rollback_span = min(tip_header.height, DEFAULT_MAX_ROLLBACK * 2)
        payload = encode_get_body_pack_payload(
            top_height=tip_header.height,
            top_hash=bytes.fromhex(tip_header.hash),
            flag_perishable=BODY_FLAG_FULL,
            flag_eternal=BODY_FLAG_FULL,
            count_extra=count_extra,
            block0=0,
            horizon_lo1=tip_header.height - rollback_span,
            horizon_hi1=tip_header.height,
        )
        expected = {MessageType.BODY_PACK}

    connection.send(MessageType.GET_BODY_PACK, payload)
    _log(
        connection.verbose,
        f"[*] {endpoint} requested block body for height {target_header.height}",
    )

    message_type, payload = _recv_until(
        connection,
        endpoint=endpoint,
        expected=expected,
        timeout=timeout,
    )
    if message_type == MessageType.BODY:
        return deserialize_body_payload(payload, target_header)
    if message_type == MessageType.BODY_PACK:
        return deserialize_body_pack_payload(payload, target_header)

    raise RuntimeError(f"unexpected message while waiting for body: {message_name(message_type)}")


def run_block_fetch(config: BlockFetchConfig, writer: JsonLineWriter) -> BlockFetchResult:
    """Fetch a single Beam block by height and persist a capture record.

    This high-level helper performs a one-shot block retrieval from a peer
    speaking the native Beam P2P protocol. The routine performs the following
    steps:
      1. Establish a `BeamConnection` to `config.endpoint` and perform a handshake.
      2. Wait for the peer's current tip header (`NEW_TIP`).
      3. Request the header for `config.height` and then request the corresponding
         block body (either `BODY` or `BODY_PACK`).
      4. Write a `BlockCaptureRecord` to `writer` containing the decoded block and
         metadata about the capture.
      5. Return a `BlockFetchResult` summarizing the fetch.

    Args:
        config: `BlockFetchConfig` containing the target endpoint, height, timeouts,
            optional fork hashes, and verbosity flag.
        writer: `JsonLineWriter` used to persist a single `BlockCaptureRecord` for
            the captured block. The writer is expected to implement `write(record)`.

    Returns:
        `BlockFetchResult` with summary information including the node address,
        requested and resolved heights/hashes, input/output/kernel counts, and
        the total duration in seconds.

    Raises:
        RuntimeError: If protocol errors occur (unexpected message types, data missing,
            or the peer closes the connection). Other exceptions from the
            underlying `BeamConnection` or writer may also propagate.

    Side effects:
        - Opens a network connection and performs I/O with the remote node.
        - Writes one JSON line using `writer.write()`.
    """
    endpoint = format_address(config.endpoint)
    started = time.monotonic()

    connection = BeamConnection(
        host=config.endpoint[0],
        port=config.endpoint[1],
        connect_timeout=config.connect_timeout,
        read_timeout=max(config.request_timeout, 1.0),
        verbose=config.verbose,
    )

    try:
        connection.connect()
        connection.handshake(0, config.fork_hashes)

        tip_header = _wait_for_tip_header(connection, endpoint, config.request_timeout)
        target_header = _request_header(
            connection,
            endpoint=endpoint,
            height=config.height,
            timeout=config.request_timeout,
        )
        decoded_block = _request_body(
            connection,
            endpoint=endpoint,
            target_header=target_header,
            tip_header=tip_header,
            timeout=config.request_timeout,
        )

        writer.write(
            BlockCaptureRecord(
                node=endpoint,
                requested_height=config.height,
                resolved_height=decoded_block.header.height,
                resolved_hash=decoded_block.header.hash,
                captured_at=utc_now_iso(),
                decoded=decoded_block,
            )
        )
    finally:
        connection.close()

    duration = time.monotonic() - started
    return BlockFetchResult(
        node=endpoint,
        requested_height=config.height,
        resolved_height=decoded_block.header.height,
        resolved_hash=decoded_block.header.hash,
        inputs=decoded_block.counts.inputs,
        outputs=decoded_block.counts.outputs,
        kernels=decoded_block.counts.kernels,
        duration_seconds=duration,
    )