"""Block header and body deserializers for Beam block fetch mode."""

from __future__ import annotations

import hashlib
import math

from src.deserializers.deserializer_core import BufferReader, DeserializationError
from src.deserializers.deserializer_kernels import deserialize_kernel
from src.deserializers.deserializer_proofs import (
    deserialize_recovery_asset_proof,
    deserialize_recovery_confidential_range_proof,
    deserialize_recovery_public_range_proof,
)
from src.deserializers.deserializer_tx import deserialize_input, deserialize_output
from src.protocol_models import (
    BlockHeader,
    BlockOutput,
    DecodedBlock,
    TxCounts,
    TxOutput,
)


HEADER_POW_INDICES_SIZE = 104
MAINNET_FORK_HEIGHTS = (0, 321321, 777777, 1280000, 1820000, 1920000)
MAINNET_FORK3_HEIGHT = MAINNET_FORK_HEIGHTS[3]


def _update_hash_compact_uint(hasher: "hashlib._Hash", value: int) -> None:
    """Encode an unsigned integer in compact varint form and feed it to `hasher`.

    The encoding uses a variable-length little-endian format where each byte
    contains 7 bits of payload and the high bit (0x80) indicates continuation.
    Encoded bytes are passed to the supplied `hasher` via its `update()`
    method.

    Args:
        hasher: A hashlib-like object implementing `update(bytes)`.
        value: Non-negative integer to encode and hash.

    Raises:
        DeserializationError: If `value` is negative.
    """

    if value < 0:
        raise DeserializationError(f"hash integer must be unsigned, got {value}")

    while value >= 0x80:
        hasher.update(bytes(((value & 0x7F) | 0x80,)))
        value >>= 7
    hasher.update(bytes((value,)))


def _find_mainnet_fork_index(height: int) -> int:
    """Return the active MAINNET fork index for the given block height.

    Scans the `MAINNET_FORK_HEIGHTS` table and returns the largest index
    such that `height >= MAINNET_FORK_HEIGHTS[index]`.

    Args:
        height: Block height (non-negative integer).

    Returns:
        The 0-based fork index applicable at `height`.
    """

    index = 0
    for candidate, fork_height in enumerate(MAINNET_FORK_HEIGHTS):
        if height >= fork_height:
            index = candidate
        else:
            break
    return index


def _get_rules_hash(height: int, peer_fork_hashes: list[bytes]) -> bytes | None:
    """Resolve the rules hash for `height` using a peer's fork-hash suffix.

    Beam peers advertise a suffix of the mainnet fork table in their Login
    payloads. This function determines which peer-supplied fork hash maps to
    the local fork index for `height`. For early forks (index < 2) no rules
    hash is required and the function returns ``None``.

    Args:
        height: Block height for which to resolve the rules hash.
        peer_fork_hashes: A list of fork-hash bytes supplied by the peer.

    Returns:
        The resolved rules hash as raw bytes, or ``None`` when not applicable.

    Raises:
        DeserializationError: If the peer payload is missing required fork
            hashes or exposes an inconsistent/unknown fork table suffix.
    """

    fork_index = _find_mainnet_fork_index(height)
    if fork_index < 2:
        return None

    if not peer_fork_hashes:
        raise DeserializationError(
            "peer Login payload did not include any fork hashes needed to resolve "
            f"the rules hash for height {height}"
        )

    if len(peer_fork_hashes) > len(MAINNET_FORK_HEIGHTS):
        raise DeserializationError(
            "peer Login payload exposed more fork hashes than the supported "
            "default Beam mainnet table"
        )

    # Beam peers send a suffix of the enabled fork table in Login, not a
    # fork-0-indexed list. On current mainnet this is often just the active
    # fork hash.
    start_index = len(MAINNET_FORK_HEIGHTS) - len(peer_fork_hashes)
    peer_index = fork_index - start_index
    if 0 <= peer_index < len(peer_fork_hashes):
        return peer_fork_hashes[peer_index]

    raise DeserializationError(
        "peer Login payload only exposed fork hashes for mainnet fork indexes "
        f"{start_index}..{len(MAINNET_FORK_HEIGHTS) - 1}; cannot resolve the "
        f"rules hash for height {height}"
    )


def _difficulty_to_float(packed: int) -> float:
    """Convert a packed difficulty integer into a floating-point value.

    Beam packs difficulty with the top byte representing the exponent (order)
    and the lower 24 bits representing the mantissa. This reconstructs the
    floating-point difficulty using :func:`math.ldexp`.

    Args:
        packed: Packed difficulty integer.

    Returns:
        Floating-point difficulty.
    """

    order = packed >> 24
    mantissa = (1 << 24) | (packed & ((1 << 24) - 1))
    return math.ldexp(mantissa, order - 24)


def _compute_block_hash(
    *,
    height: int,
    previous_hash: bytes,
    chainwork: bytes,
    kernels: bytes,
    definition: bytes,
    timestamp: int,
    packed_difficulty: int,
    rules_hash: bytes | None,
    pow_indices: bytes,
    pow_nonce: bytes,
) -> bytes:
    """Compute the SHA-256 block header hash used by Beam nodes.

    The hash is computed by serializing the header fields in a deterministic
    order and feeding them into SHA-256. Compact varint encodings are used
    for integer fields (height, timestamp, packed difficulty).

    Args:
        height: Block height.
        previous_hash: Raw previous block hash (bytes).
        chainwork: Raw chainwork bytes.
        kernels: Raw kernels hash bytes.
        definition: Raw block definition bytes.
        timestamp: Block timestamp as integer.
        packed_difficulty: Packed difficulty integer.
        rules_hash: Optional rules hash to include for certain mainnet forks.
        pow_indices: Raw PoW indices bytes (HEADER_POW_INDICES_SIZE length).
        pow_nonce: Raw PoW nonce bytes (8 bytes).

    Returns:
        The 32-byte SHA-256 digest of the serialized header.
    """

    hasher = hashlib.sha256()
    _update_hash_compact_uint(hasher, height)
    hasher.update(previous_hash)
    hasher.update(chainwork)
    hasher.update(kernels)
    hasher.update(definition)
    _update_hash_compact_uint(hasher, timestamp)
    _update_hash_compact_uint(hasher, packed_difficulty)

    if rules_hash is not None and _find_mainnet_fork_index(height) >= 2:
        hasher.update(rules_hash)

    hasher.update(pow_indices)
    hasher.update(pow_nonce)
    return hasher.digest()


def _read_header_element(reader: BufferReader) -> tuple[str, str, int, int, bytes, bytes]:
    """Read a header element from ``reader`` and return its components.

    The function reads the following sequence from the reader:
    - `kernels` (32-byte hash, returned as hex string)
    - `definition` (32-byte hash, returned as hex string)
    - `timestamp` (varuint)
    - `pow_indices` (fixed-size bytes)
    - `packed_difficulty` (varuint)
    - `pow_nonce` (8 bytes)

    Args:
        reader: BufferReader positioned at the start of a header element.

    Returns:
        A tuple (kernels_hex, definition_hex, timestamp, packed_difficulty,
        pow_indices_bytes, pow_nonce_bytes).
    """

    kernels = reader.read_hash32()
    definition = reader.read_hash32()
    timestamp = reader.read_var_uint()
    pow_indices = reader.read_bytes(HEADER_POW_INDICES_SIZE)
    packed_difficulty = reader.read_var_uint()
    pow_nonce = reader.read_bytes(8)
    return kernels, definition, timestamp, packed_difficulty, pow_indices, pow_nonce


def _build_block_header(
    *,
    height: int,
    previous_hash: str,
    chainwork: str,
    kernels: str,
    definition: str,
    timestamp: int,
    packed_difficulty: int,
    pow_indices: bytes,
    pow_nonce: bytes,
    peer_fork_hashes: list[bytes],
) -> BlockHeader:
    """Construct a :class:`BlockHeader` model from low-level header fields.

    This converts hex-encoded inputs into raw bytes where necessary, computes
    the canonical block hash and fills derived fields such as the floating
    point difficulty and hex-encoded PoW fields.

    Args:
        height: Block height.
        previous_hash: Hex string of previous block hash.
        chainwork: Hex string representing chainwork.
        kernels: Hex string of kernels hash.
        definition: Hex string of the block definition.
        timestamp: Block timestamp as integer.
        packed_difficulty: Packed difficulty integer.
        pow_indices: Raw pow indices bytes.
        pow_nonce: Raw pow nonce bytes.
        peer_fork_hashes: List of fork-hash bytes from the peer Login payload.

    Returns:
        A populated :class:`BlockHeader` instance with computed `hash` and
        derived metadata.
    """

    rules_hash = _get_rules_hash(height, peer_fork_hashes)
    block_hash = _compute_block_hash(
        height=height,
        previous_hash=bytes.fromhex(previous_hash),
        chainwork=bytes.fromhex(chainwork),
        kernels=bytes.fromhex(kernels),
        definition=bytes.fromhex(definition),
        timestamp=timestamp,
        packed_difficulty=packed_difficulty,
        rules_hash=rules_hash,
        pow_indices=pow_indices,
        pow_nonce=pow_nonce,
    )
    return BlockHeader(
        height=height,
        hash=block_hash.hex(),
        previous_hash=previous_hash,
        chainwork=chainwork,
        kernels=kernels,
        definition=definition,
        timestamp=timestamp,
        packed_difficulty=packed_difficulty,
        difficulty=_difficulty_to_float(packed_difficulty),
        rules_hash=rules_hash.hex() if rules_hash is not None else None,
        pow_indices_hex=pow_indices.hex(),
        pow_nonce_hex=pow_nonce.hex(),
    )


def deserialize_new_tip_payload(
    payload: bytes,
    peer_fork_hashes: list[bytes],
) -> BlockHeader:
    """Deserialize a ``NewTip`` payload into a :class:`BlockHeader`.

    This parses a single header encoded in the NewTip wire format and
    resolves any fork-dependent rules hashes using `peer_fork_hashes`.

    Args:
        payload: Raw payload bytes containing the NewTip header.
        peer_fork_hashes: Fork-hash bytes advertised by the peer (Login
            payload) used to resolve rules hashes when applicable.

    Returns:
        A :class:`BlockHeader` instance with computed fields.

    Raises:
        DeserializationError: If the payload contains trailing bytes or is
            otherwise malformed.
    """
    reader = BufferReader(payload)
    height = reader.read_var_uint()
    previous_hash = reader.read_hash32()
    chainwork = reader.read_hash32()
    kernels, definition, timestamp, packed_difficulty, pow_indices, pow_nonce = (
        _read_header_element(reader)
    )

    if reader.remaining != 0:
        raise DeserializationError(
            f"{reader.remaining} trailing byte(s) left after NewTip header parse"
        )

    return _build_block_header(
        height=height,
        previous_hash=previous_hash,
        chainwork=chainwork,
        kernels=kernels,
        definition=definition,
        timestamp=timestamp,
        packed_difficulty=packed_difficulty,
        pow_indices=pow_indices,
        pow_nonce=pow_nonce,
        peer_fork_hashes=peer_fork_hashes,
    )


def deserialize_header_pack(
    payload: bytes,
    peer_fork_hashes: list[bytes],
) -> BlockHeader:
    """Deserialize an ``HdrPack`` payload containing exactly one header.

    HdrPack may contain multiple headers; this helper expects exactly one and
    will raise on any other count.

    Args:
        payload: Raw payload bytes containing the HdrPack.
        peer_fork_hashes: Fork-hash bytes advertised by the peer (Login
            payload) used to resolve rules hashes when applicable.

    Returns:
        The parsed :class:`BlockHeader`.

    Raises:
        DeserializationError: If the header count is not exactly one or if
            trailing data remains after parsing.
    """
    reader = BufferReader(payload)
    height = reader.read_var_uint()
    previous_hash = reader.read_hash32()
    chainwork = reader.read_hash32()
    count = reader.read_var_uint()
    if count != 1:
        raise DeserializationError(f"expected exactly one header in HdrPack, got {count}")

    kernels, definition, timestamp, packed_difficulty, pow_indices, pow_nonce = (
        _read_header_element(reader)
    )

    if reader.remaining != 0:
        raise DeserializationError(
            f"{reader.remaining} trailing byte(s) left after HdrPack parse"
        )

    return _build_block_header(
        height=height,
        previous_hash=previous_hash,
        chainwork=chainwork,
        kernels=kernels,
        definition=definition,
        timestamp=timestamp,
        packed_difficulty=packed_difficulty,
        pow_indices=pow_indices,
        pow_nonce=pow_nonce,
        peer_fork_hashes=peer_fork_hashes,
    )


def deserialize_block_output(reader: BufferReader, height: int) -> BlockOutput:
    """Deserialize a Recovery1 block output from ``reader``.

    The Recovery1 output format begins with a flags byte that controls which
    optional fields follow. The function decodes the commitment (x-coordinate
    of the EC point), optional confidential/public range proofs, optional
    incubation, optional asset proof (available only on certain forks), and
    optional extra flags.

    Args:
        reader: BufferReader positioned at the start of the output payload.
        height: Block height used to determine fork-dependent fields
            (e.g. whether asset proofs are expected).

    Returns:
        A :class:`BlockOutput` model populated from the payload.

    Raises:
        DeserializationError: If the payload is truncated or malformed.
    """
    flags = reader.read_u8()
    commitment = reader.read_point_x(bool(flags & 1))
    confidential_proof = (
        deserialize_recovery_confidential_range_proof(reader) if flags & 4 else None
    )
    public_proof = (
        deserialize_recovery_public_range_proof(reader) if flags & 8 else None
    )
    incubation = reader.read_var_uint() if flags & 0x10 else None

    asset_proof = None
    if flags & 0x20 and height >= MAINNET_FORK3_HEIGHT:
        asset_proof = deserialize_recovery_asset_proof(reader)

    return BlockOutput(
        commitment=commitment,
        coinbase=bool(flags & 2),
        recovery_only=True,
        confidential_proof=confidential_proof,
        public_proof=public_proof,
        incubation=incubation,
        asset_proof=asset_proof,
        extra_flags=reader.read_u8() if flags & 0x80 else None,
    )


def _block_output_from_tx_output(output: TxOutput) -> BlockOutput:
    """Convert a transaction-level ``TxOutput`` into a block-level ``BlockOutput``.

    Args:
        output: The ``TxOutput`` instance produced by :func:`deserialize_output`.

    Returns:
        A :class:`BlockOutput` with fields copied from the transaction output.
    """

    return BlockOutput(
        commitment=output.commitment,
        coinbase=output.coinbase,
        recovery_only=False,
        confidential_proof=output.confidential_proof,
        public_proof=output.public_proof,
        incubation=output.incubation,
        asset_proof=output.asset_proof,
        extra_flags=output.extra_flags,
    )


def _read_body_buffers(reader: BufferReader) -> tuple[bytes, bytes]:
    """Read the two byte buffers that compose a block body: perishable and eternal.

    Beam body payloads encode two length-prefixed byte buffers in sequence:
    - perishable: contains inputs, outputs and optional full-block appendix
    - eternal: contains kernels and related data

    Args:
        reader: BufferReader positioned at the start of the buffers.

    Returns:
        Tuple of (perishable_bytes, eternal_bytes).
    """

    return reader.read_byte_buffer(), reader.read_byte_buffer()


def _deserialize_full_perishable(
    perishable: bytes,
    header: BlockHeader,
) -> tuple[list, list[BlockOutput], int, str | None]:
    """Parse a 'full' perishable payload format used by standard blocks.

    The full format layout:
    - offset: scalar (reader.read_scalar)
    - input_count: 4-byte big-endian unsigned int
    - inputs: `input_count` entries parsed with :func:`deserialize_input`
    - output_count: 4-byte big-endian unsigned int
    - outputs: `output_count` entries parsed with :func:`deserialize_output`

    Args:
        perishable: Raw bytes of the perishable buffer.
        header: BlockHeader for contextual needs (not required by full format).

    Returns:
        A tuple (inputs, outputs, output_count, offset) where `inputs` is a
        list of deserialized inputs, `outputs` is a list of :class:`BlockOutput`,
        `output_count` is the number of outputs, and `offset` is the block
        offset scalar (hex string) read from the buffer.

    Raises:
        DeserializationError: If trailing bytes remain after parsing or the
            buffer is otherwise malformed.
    """

    reader = BufferReader(perishable)
    offset = reader.read_scalar()

    input_count = reader.read_big_uint(4)
    inputs = [deserialize_input(reader) for _ in range(input_count)]

    output_count = reader.read_big_uint(4)
    outputs = [
        _block_output_from_tx_output(deserialize_output(reader))
        for _ in range(output_count)
    ]

    if reader.remaining != 0:
        raise DeserializationError(
            f"{reader.remaining} trailing byte(s) left after full block perishable parse"
        )

    return inputs, outputs, output_count, offset


def _deserialize_recovery_perishable(
    perishable: bytes,
    header: BlockHeader,
) -> tuple[list, list[BlockOutput], int, str | None]:
    """Parse a Recovery1-style perishable payload.

    Recovery perishable payloads contain a fixed-width input list followed by
    a varuint output count and that many recovery-style block outputs. If
    additional bytes are present they may contain an `offset` scalar and an
    appended 'full' input/output section that provides full transaction
    context for recovery use-cases.

    Args:
        perishable: Raw perishable buffer bytes.
        header: BlockHeader used to determine fork-dependent behaviors
            (e.g. asset proofs availability).

    Returns:
        Either (inputs, outputs, output_count, offset) for the recovery-only
        case, or (full_inputs, full_outputs, full_output_count, offset) when
        the peer included the appended full-block transaction data.

    Raises:
        DeserializationError: If the payload is truncated or malformed.
    """

    reader = BufferReader(perishable)

    input_count = reader.read_big_uint(4)
    inputs = [deserialize_input(reader) for _ in range(input_count)]

    output_count = reader.read_var_uint()
    outputs = [deserialize_block_output(reader, header.height) for _ in range(output_count)]

    offset = None
    if reader.remaining:
        if reader.remaining < 32:
            raise DeserializationError(
                "recovery block payload ended before the block offset could be read"
            )

        offset = reader.read_scalar()
        if reader.remaining:
            full_input_count = reader.read_big_uint(4)
            full_inputs = [deserialize_input(reader) for _ in range(full_input_count)]

            full_output_count = reader.read_big_uint(4)
            full_outputs = [
                _block_output_from_tx_output(deserialize_output(reader))
                for _ in range(full_output_count)
            ]

            if reader.remaining != 0:
                raise DeserializationError(
                    f"{reader.remaining} trailing byte(s) left after Recovery1 block parse"
                )

            return full_inputs, full_outputs, full_output_count, offset

    return inputs, outputs, output_count, offset


def _deserialize_perishable(
    perishable: bytes,
    header: BlockHeader,
) -> tuple[list, list[BlockOutput], int, str | None]:
    """Attempt to parse `perishable` as either full or Recovery1 format.

    This helper first tries the full-block parser and falls back to the
    Recovery1 parser on failure. If both attempts fail a combined
    DeserializationError is raised that includes both diagnostic messages.

    Args:
        perishable: Raw perishable buffer bytes.
        header: BlockHeader for context passed to the underlying parsers.

    Returns:
        A tuple as returned by the successful underlying parser.

    Raises:
        DeserializationError: If neither format parses successfully.
    """

    try:
        return _deserialize_full_perishable(perishable, header)
    except DeserializationError as full_error:
        try:
            return _deserialize_recovery_perishable(perishable, header)
        except DeserializationError as recovery_error:
            raise DeserializationError(
                "failed to parse block perishable payload as either full or Recovery1 "
                f"format; full error: {full_error}; recovery error: {recovery_error}"
            ) from recovery_error


def _deserialize_body_buffers(
    perishable: bytes,
    eternal: bytes,
    header: BlockHeader,
) -> DecodedBlock:
    """Deserialize perishable/eternal buffers into a :class:`DecodedBlock`.

    Workflow:
    1. Parse `perishable` using :func:`_deserialize_perishable` to obtain the
       inputs, outputs, output count and optional offset.
    2. Parse `eternal` by reading a 4-byte kernel count word; the top bit
       signals `kernels_mixed` and the remaining 31 bits are the kernel
       count. Each kernel is deserialized with :func:`deserialize_kernel`.
    3. Validate there are no trailing bytes in the eternal buffer and return
       a :class:`DecodedBlock` assembled from the parsed components.

    Args:
        perishable: Raw perishable buffer bytes.
        eternal: Raw eternal buffer bytes.
        header: BlockHeader corresponding to these buffers.

    Returns:
        A fully populated :class:`DecodedBlock`.

    Raises:
        DeserializationError: If any payload is malformed or contains trailing
            bytes after parsing.
    """

    inputs, outputs, output_count, offset = _deserialize_perishable(perishable, header)
    input_count = len(inputs)

    eternal_reader = BufferReader(eternal)
    kernel_count_raw = eternal_reader.read_big_uint(4)
    kernels_mixed = bool(kernel_count_raw & (1 << 31))
    kernel_count = kernel_count_raw & 0x7FFFFFFF
    kernels = [
        deserialize_kernel(eternal_reader, assume_std=not kernels_mixed)
        for _ in range(kernel_count)
    ]

    if eternal_reader.remaining != 0:
        raise DeserializationError(
            f"{eternal_reader.remaining} trailing byte(s) left after block kernel parse"
        )

    return DecodedBlock(
        header=header,
        inputs=inputs,
        outputs=outputs,
        kernels=kernels,
        counts=TxCounts(
            inputs=input_count,
            outputs=output_count,
            kernels=kernel_count,
            kernels_mixed=kernels_mixed,
        ),
        offset=offset,
    )


def deserialize_body_payload(payload: bytes, header: BlockHeader) -> DecodedBlock:
    """Deserialize a single-block ``Body`` payload into a :class:`DecodedBlock`.

    The payload contains two length-prefixed buffers (perishable and
    eternal). This function extracts them and delegates to
    :func:`_deserialize_body_buffers` for full parsing.

    Args:
        payload: Raw Body payload bytes received from the peer.
        header: The corresponding :class:`BlockHeader` for contextual parsing.

    Returns:
        A :class:`DecodedBlock` containing inputs, outputs, kernels and
        counts for the single block represented by this payload.

    Raises:
        DeserializationError: If the payload is malformed or trailing bytes
            remain after buffer extraction.
    """

    reader = BufferReader(payload)
    perishable, eternal = _read_body_buffers(reader)
    if reader.remaining != 0:
        raise DeserializationError(
            f"{reader.remaining} trailing byte(s) left after Body parse"
        )
    return _deserialize_body_buffers(perishable, eternal, header)


def deserialize_body_pack_payload(payload: bytes, header: BlockHeader) -> DecodedBlock:
    """Deserialize a ``BodyPack`` payload and return the first block.

    A BodyPack may contain multiple body entries. This helper extracts the
    first perishable/eternal pair and skips the remaining entries.

    Args:
        payload: Raw BodyPack payload bytes.
        header: The header corresponding to the first body entry.

    Returns:
        The :class:`DecodedBlock` for the first body in the pack.

    Raises:
        DeserializationError: If the pack declares zero bodies, or trailing
            bytes remain after parsing.
    """

    reader = BufferReader(payload)
    body_count = reader.read_var_uint()
    if body_count == 0:
        raise DeserializationError("BodyPack did not contain any block bodies")

    perishable, eternal = _read_body_buffers(reader)
    for _ in range(body_count - 1):
        _read_body_buffers(reader)

    if reader.remaining != 0:
        raise DeserializationError(
            f"{reader.remaining} trailing byte(s) left after BodyPack parse"
        )
    return _deserialize_body_buffers(perishable, eternal, header)