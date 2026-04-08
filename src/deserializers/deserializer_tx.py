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
    """Deserialize a NewTransactionPayload from a bytes payload.

    The payload layout is:
      - transaction_present: bool
      - if present: serialized Transaction
      - context_present: bool
      - if present: 32-byte hash
      - fluff: bool

    Args:
        payload: Raw bytes containing a serialized NewTransactionPayload.

    Returns:
        NewTransactionPayload: Parsed payload object.

    Raises:
        DeserializationError: If trailing bytes remain after parsing.
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
    """Deserialize a Transaction from the provided BufferReader.

    Reads inputs, outputs, and kernels as encoded in the transaction payload,
    builds the `TxCounts` summary and reads the transaction `offset` scalar.

    Args:
        reader: BufferReader positioned at the start of the transaction payload.

    Returns:
        Transaction: The deserialized transaction object.
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
    """Deserialize a single transaction input.

    Format:
      - flags: 1 byte
      - commitment: point X (compressed flag determined by flags bit 0)

    Args:
        reader: BufferReader positioned at the start of the input.

    Returns:
        TxInput: The deserialized input containing the commitment.
    """
    flags = reader.read_u8()
    return TxInput(commitment=reader.read_point_x(bool(flags & 1)))


def deserialize_output(reader: BufferReader) -> TxOutput:
    """Deserialize a single transaction output.

    The output starts with a flags byte that controls which optional fields
    follow (coinbase, proofs, incubation, asset proof, extra flags, etc.).

    Args:
        reader: BufferReader positioned at the start of the output.

    Returns:
        TxOutput: The deserialized output with optional fields set to `None`
            when they are not present.
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
