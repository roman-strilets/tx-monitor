"""Top-level transaction deserializers (split out from the big module).
"""
from src.deserializers.deserializer_core import BufferReader
from src.deserializers.deserializer_kernels import deserialize_kernel
from src.deserializers.deserializer_proofs import (
    deserialize_confidential_range_proof,
    deserialize_public_range_proof,
    deserialize_asset_proof,
)
from src.protocol_models import NewTransactionPayload, Transaction, TxCounts, TxInput, TxOutput


def deserialize_new_transaction_payload(payload: bytes) -> NewTransactionPayload:
    """Deserialize a `NewTransactionPayload` from raw bytes.

    The function parses a compact message describing whether a full
    transaction is included plus an optional context and a fluff flag.

    Binary layout expected (in order):
      - `transaction_present`: bool (1 byte)
      - if `transaction_present` is True: serialized `Transaction` (variable length)
      - `context_present`: bool (1 byte)
      - if `context_present` is True: 32-byte context hash
      - `fluff`: bool (1 byte)

    The routine uses a `BufferReader` to consume the stream. If extra
    bytes remain after parsing the declared fields, a
    `DeserializationError` is raised to signal malformed/trailing data.

    Args:
        payload: Raw bytes containing a serialized `NewTransactionPayload`.

    Returns:
        NewTransactionPayload: Parsed payload object with attributes:
            - `transaction_present` (bool)
            - `transaction` (Transaction | None)
            - `context` (bytes | None) — 32-byte hash when present
            - `fluff` (bool)

    Raises:
        DeserializationError: If trailing bytes remain after parsing or if
            an underlying reader call detects malformed input.
    """
    reader = BufferReader(payload)

    transaction_present = reader.read_bool()
    transaction = deserialize_transaction(reader) if transaction_present else None

    context_present = reader.read_bool()
    context = reader.read_hash32() if context_present else None
    fluff = reader.read_bool()

    if reader.remaining != 0:
        from src.deserializers.deserializer_core import DeserializationError

        raise DeserializationError(
            f"{reader.remaining} trailing byte(s) left after NewTransaction parse"
        )

    return NewTransactionPayload(
        transaction_present=transaction_present,
        transaction=transaction,
        context=context,
        fluff=fluff,
    )


def deserialize_transaction(reader: BufferReader) -> Transaction:
    """Deserialize a `Transaction` from the provided `BufferReader`.

    This function consumes the reader sequentially and reconstructs the
    transaction components: inputs, outputs, kernels and the transaction
    offset. The expected layout is:

      1. `input_count` — 4-byte big-endian unsigned integer.
      2. `inputs` — sequence of `input_count` inputs parsed by
         `deserialize_input`.
      3. `output_count` — 4-byte big-endian unsigned integer.
      4. `outputs` — sequence of `output_count` outputs parsed by
         `deserialize_output`.
      5. `kernel_count_raw` — 4-byte big-endian unsigned integer. The
         most-significant bit (0x80000000) encodes `kernels_mixed` and the
         lower 31 bits encode the kernel count.
      6. `kernels` — sequence of kernels parsed by `deserialize_kernel`.
         If `kernels_mixed` is False, kernels are assumed to be in the
         standard format; otherwise mixed formats are allowed.
      7. `offset` — scalar value read via `reader.read_scalar()`.

    The function also constructs a `TxCounts` helper summarizing the
    number of inputs, outputs and kernels and whether kernels are mixed.

    Args:
        reader: `BufferReader` positioned at the start of the transaction
            payload.

    Returns:
        Transaction: The deserialized transaction object containing:
            - `inputs` (List[TxInput])
            - `outputs` (List[TxOutput])
            - `kernels` (List[Kernel])
            - `counts` (TxCounts) with fields `inputs`, `outputs`,
              `kernels`, `kernels_mixed`
            - `offset` (scalar)

    Raises:
        DeserializationError: Propagated from lower-level reader/deserializer
            calls when input is malformed or truncated.
    """
    input_count = reader.read_big_uint(4)
    inputs = [deserialize_input(reader) for _ in range(input_count)]

    output_count = reader.read_big_uint(4)
    outputs = [deserialize_output(reader) for _ in range(output_count)]

    kernel_count_raw = reader.read_big_uint(4)
    kernels_mixed = bool(kernel_count_raw & (1 << 31))
    kernel_count = kernel_count_raw & 0x7FFFFFFF
    kernels = [
        deserialize_kernel(reader, assume_std=not kernels_mixed)
        for _ in range(kernel_count)
    ]

    return Transaction(
        inputs=inputs,
        outputs=outputs,
        kernels=kernels,
        counts=TxCounts(
            inputs=input_count,
            outputs=output_count,
            kernels=kernel_count,
            kernels_mixed=kernels_mixed,
        ),
        offset=reader.read_scalar(),
    )


def deserialize_input(reader: BufferReader) -> TxInput:
    """Deserialize a single transaction input from the reader.

    Input format (in order):
      - `flags` (1 byte): bitfield where bit 0 (0x01) indicates whether the
        commitment is encoded as the compressed X-coordinate. Other bits are
        reserved and ignored by this parser.
      - `commitment`: elliptic-curve point encoded as an X-only point; the
        `compressed` boolean passed to `reader.read_point_x` is derived from
        `flags & 0x01`.

    Args:
        reader: `BufferReader` positioned at the start of the input record.

    Returns:
        TxInput: The deserialized input with the `commitment` field set.

    Raises:
        DeserializationError: If the reader fails to parse the flags or the
            expected point data.
    """
    flags = reader.read_u8()
    return TxInput(commitment=reader.read_point_x(bool(flags & 1)))


def deserialize_output(reader: BufferReader) -> TxOutput:
        """Deserialize a single transaction output from the reader.

        The output begins with a single `flags` byte that controls which
        optional fields are present and the encoding of the commitment. Bit
        definitions (mask values shown):

            - 0x01 (bit 0): commitment compression flag; passed as `compressed`
                to `reader.read_point_x`.
            - 0x02 (bit 1): `coinbase` flag; when set, marks the output as
                coinbase-related.
            - 0x04 (bit 2): confidential range proof present; parsed with
                `deserialize_confidential_range_proof`.
            - 0x08 (bit 3): public range proof present; parsed with
                `deserialize_public_range_proof`.
            - 0x10 (bit 4): incubation present; an unsigned varint follows and is
                returned as `incubation`.
            - 0x20 (bit 5): asset proof present; parsed with
                `deserialize_asset_proof`.
            - 0x40 (bit 6): reserved (ignored by this parser).
            - 0x80 (bit 7): `extra_flags` present; a single `u8` follows.

        Fields are read in that order and any optional field that is not present
        will be represented as `None` on the returned `TxOutput`.

        Args:
                reader: `BufferReader` positioned at the start of the output record.

        Returns:
                TxOutput: The deserialized output with attributes:
                        - `commitment` (point)
                        - `coinbase` (bool)
                        - `confidential_proof` (optional proof object)
                        - `public_proof` (optional proof object)
                        - `incubation` (optional int)
                        - `asset_proof` (optional proof object)
                        - `extra_flags` (optional int)

        Raises:
                DeserializationError: If the reader fails to parse any expected
                        field or if data is truncated.
        """
        flags = reader.read_u8()
        return TxOutput(
                commitment=reader.read_point_x(bool(flags & 1)),
                coinbase=bool(flags & 2),
                confidential_proof=deserialize_confidential_range_proof(reader) if flags & 4 else None,
                public_proof=deserialize_public_range_proof(reader) if flags & 8 else None,
                incubation=reader.read_var_uint() if flags & 0x10 else None,
                asset_proof=deserialize_asset_proof(reader) if flags & 0x20 else None,
                extra_flags=reader.read_u8() if flags & 0x80 else None,
        )
