"""Deserializer for Beam NewTransaction message payloads.

Decodes the binary-serialised transaction structure produced by a Beam node
into a nested dictionary that can be JSON-serialised.  Covers all kernel
subtypes known as of extension version 11, including Lelantus / shielded
I/O, asset operations, and EVM invocations.
"""
from dataclasses import dataclass
from enum import IntEnum

from .codec import decode_uint


ASSET_PROOF_N = 4
ASSET_PROOF_M = 3
INNER_PRODUCT_CYCLES = 6


class KernelSubtype(IntEnum):
    """Beam protocol kernel subtype codes."""

    STD = 1
    ASSET_EMIT = 2
    SHIELDED_OUTPUT = 3
    SHIELDED_INPUT = 4
    ASSET_CREATE = 5
    ASSET_DESTROY = 6
    CONTRACT_CREATE = 7
    CONTRACT_INVOKE = 8
    EVM_INVOKE = 9


_KERNEL_SUBTYPE_NAMES = {
    KernelSubtype.STD: "Std",
    KernelSubtype.ASSET_EMIT: "AssetEmit",
    KernelSubtype.SHIELDED_OUTPUT: "ShieldedOutput",
    KernelSubtype.SHIELDED_INPUT: "ShieldedInput",
    KernelSubtype.ASSET_CREATE: "AssetCreate",
    KernelSubtype.ASSET_DESTROY: "AssetDestroy",
    KernelSubtype.CONTRACT_CREATE: "ContractCreate",
    KernelSubtype.CONTRACT_INVOKE: "ContractInvoke",
    KernelSubtype.EVM_INVOKE: "EvmInvoke",
}


def _get_kernel_subtype_name(subtype: KernelSubtype) -> str:
    """Get human-readable name for a kernel subtype.
    
    Args:
        subtype: Kernel subtype enum member
    
    Returns:
        Human-readable kernel subtype name
    """
    return _KERNEL_SUBTYPE_NAMES.get(subtype, f"Unknown({subtype})")


class DeserializationError(ValueError):
    """Raised when a transaction payload cannot be parsed.

    Inherits from :class:`ValueError` so callers can catch it broadly
    alongside other data-format errors.
    """
    pass


@dataclass(frozen=True)
class SigmaConfig:
    """Parameters that define the dimensions of a Sigma / Lelantus proof.

    Attributes:
        n: Ring size base.
        M: Exponent (number of decomposition levels).  The full ring size is
           ``n ** M``.
    """
    n: int
    M: int

    @property
    def f_count(self) -> int:
        return self.M * (self.n - 1)


class BufferReader:
    """Cursor-based reader over an immutable bytes buffer.

    Provides typed read helpers (integers, booleans, fixed-width hex strings,
    elliptic-curve points) that advance an internal offset and raise
    :class:`DeserializationError` on underflow.
    """

    def __init__(self, data: bytes):
        """Wrap *data* for sequential reading.

        Args:
            data: Immutable bytes buffer to read from.
        """
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        """Current read position as a byte offset from the start of the buffer."""
        return self._offset

    @property
    def remaining(self) -> int:
        """Number of bytes not yet consumed."""
        return len(self._data) - self._offset

    def read_bytes(self, size: int) -> bytes:
        """Read and return exactly *size* bytes, advancing the offset.

        Args:
            size: Number of bytes to consume.

        Returns:
            Bytes slice of length *size*.

        Raises:
            DeserializationError: If *size* is negative or there are fewer
                than *size* bytes remaining.
        """
        if size < 0:
            raise DeserializationError(f"negative read size: {size}")
        end = self._offset + size
        if end > len(self._data):
            raise DeserializationError(
                f"unexpected end of buffer at offset {self._offset}, need {size} bytes"
            )
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk

    def read_u8(self) -> int:
        """Read one unsigned byte."""
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        """Read one byte and return ``True`` iff it is non-zero."""
        return self.read_u8() != 0

    def read_var_uint(self) -> int:
        """Read a Beam variable-length unsigned integer.

        Raises:
            DeserializationError: On buffer underflow.
        """
        try:
            value, size = decode_uint(self._data, self._offset)
        except IndexError as exc:
            raise DeserializationError(
                f"unexpected end of compact unsigned integer at offset {self._offset}"
            ) from exc

        self._offset += size
        return value

    def read_var_int(self) -> int:
        """Read a Beam variable-length signed integer."""
        head = self.read_u8()
        negative = (head >> 7) & 1
        one_byte = (head >> 6) & 1
        value = head & 0x3F

        if one_byte:
            return -value if negative else value

        raw = int.from_bytes(self.read_bytes(value), "little") if value else 0
        return -raw if negative else raw

    def read_big_uint(self, size: int) -> int:
        """Read *size* bytes and interpret them as a big-endian unsigned integer."""
        return int.from_bytes(self.read_bytes(size), "big")

    def read_fixed_hex(self, size: int) -> str:
        """Read *size* bytes and return them as a lowercase hex string."""
        return self.read_bytes(size).hex()

    def read_scalar(self) -> str:
        """Read a 32-byte scalar and return it as a hex string."""
        return self.read_fixed_hex(32)

    def read_hash32(self) -> str:
        """Read a 32-byte hash and return it as a hex string."""
        return self.read_fixed_hex(32)

    def read_point(self) -> dict[str, object]:
        """Read a compressed elliptic-curve point (32-byte X + 1-byte Y flag)."""
        return {
            "x": self.read_fixed_hex(32),
            "y": self.read_bool(),
        }

    def read_point_x(self, y_flag: bool) -> dict[str, object]:
        """Read a 32-byte point X-coordinate, pairing it with a pre-decoded *y_flag*."""
        return {
            "x": self.read_fixed_hex(32),
            "y": y_flag,
        }

    def read_byte_buffer(self) -> bytes:
        """Read a length-prefixed byte buffer (var-uint length followed by that many bytes)."""
        size = self.read_var_uint()
        return self.read_bytes(size)


def deserialize_new_transaction_payload(payload: bytes) -> dict[str, object]:
    """Deserialize the full body of a Beam ``NewTransaction`` message.

    Args:
        payload: Raw bytes of the ``NewTransaction`` message body.

    Returns:
        Dictionary with keys ``transaction_present``, ``transaction``,
        ``context``, and ``fluff``.

    Raises:
        DeserializationError: If the payload is malformed or has trailing
            bytes after parsing completes.
    """
    reader = BufferReader(payload)

    transaction_present = reader.read_bool()
    transaction = deserialize_transaction(reader) if transaction_present else None

    context_present = reader.read_bool()
    context = reader.read_hash32() if context_present else None
    fluff = reader.read_bool()

    if reader.remaining != 0:
        raise DeserializationError(
            f"{reader.remaining} trailing byte(s) left after NewTransaction parse"
        )

    return {
        "transaction_present": transaction_present,
        "transaction": transaction,
        "context": context,
        "fluff": fluff,
    }


def deserialize_transaction(reader: BufferReader) -> dict[str, object]:
    """Deserialize a Beam transaction from *reader*.

    Reads inputs, outputs, and kernels (possibly mixed-subtype) and the
    blinding-factor offset scalar.

    Args:
        reader: Buffer positioned at the start of the transaction data.

    Returns:
        Dictionary with keys ``inputs``, ``outputs``, ``kernels``,
        ``counts``, and ``offset``.
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

    return {
        "inputs": inputs,
        "outputs": outputs,
        "kernels": kernels,
        "counts": {
            "inputs": input_count,
            "outputs": output_count,
            "kernels": kernel_count,
            "kernels_mixed": kernels_mixed,
        },
        "offset": reader.read_scalar(),
    }


def deserialize_input(reader: BufferReader) -> dict[str, object]:
    """Deserialize a single transaction input.

    Reads a flags byte whose LSB encodes the Y-parity of the commitment point.

    Args:
        reader: Buffer positioned at the start of the input.

    Returns:
        Dictionary with a ``commitment`` elliptic-curve point.
    """
    flags = reader.read_u8()
    return {
        "commitment": reader.read_point_x(bool(flags & 1)),
    }


def deserialize_output(reader: BufferReader) -> dict[str, object]:
    """Deserialize a single transaction output.

    Reads a flags byte that controls which optional fields are present:
    bit 0 – commitment Y, bit 1 – coinbase, bit 2 – confidential range proof,
    bit 3 – public range proof, bit 4 – incubation period, bit 5 – asset
    proof, bit 7 – extra flags byte.

    Args:
        reader: Buffer positioned at the start of the output.

    Returns:
        Dictionary with ``commitment`` and ``coinbase`` always present, and
        optional keys ``confidential_proof``, ``public_proof``,
        ``incubation``, ``asset_proof``, and ``extra_flags``.
    """
    flags = reader.read_u8()
    output: dict[str, object] = {
        "commitment": reader.read_point_x(bool(flags & 1)),
        "coinbase": bool(flags & 2),
    }

    if flags & 4:
        output["confidential_proof"] = deserialize_confidential_range_proof(reader)

    if flags & 8:
        output["public_proof"] = deserialize_public_range_proof(reader)

    if flags & 0x10:
        output["incubation"] = reader.read_var_uint()

    if flags & 0x20:
        output["asset_proof"] = deserialize_asset_proof(reader)

    if flags & 0x80:
        output["extra_flags"] = reader.read_u8()

    return output


def deserialize_kernel(reader: BufferReader, assume_std: bool) -> dict[str, object]:
    """Deserialize a single kernel, dispatching on subtype.

    Args:
        reader: Buffer positioned at the start of the kernel.
        assume_std: When ``True`` the subtype byte is not read from the
            buffer and ``KernelSubtype.STD`` is assumed (used for
            homogeneous-kernel transactions).

    Returns:
        Dictionary with a ``subtype`` key and subtype-specific fields.

    Raises:
        DeserializationError: For unknown or unimplemented subtypes.
    """
    subtype_id = 1 if assume_std else reader.read_u8()
    
    try:
        subtype = KernelSubtype(subtype_id)
    except ValueError:
        raise DeserializationError(f"unsupported kernel subtype: {subtype_id}")
    
    subtype_name = _get_kernel_subtype_name(subtype)

    if subtype == KernelSubtype.STD:
        return deserialize_std_kernel(reader, subtype_name)
    if subtype == KernelSubtype.ASSET_EMIT:
        return deserialize_asset_emit_kernel(reader, subtype_name)
    if subtype == KernelSubtype.SHIELDED_OUTPUT:
        return deserialize_shielded_output_kernel(reader, subtype_name)
    if subtype == KernelSubtype.SHIELDED_INPUT:
        return deserialize_shielded_input_kernel(reader, subtype_name)
    if subtype == KernelSubtype.ASSET_CREATE:
        return deserialize_asset_create_kernel(reader, subtype_name)
    if subtype == KernelSubtype.ASSET_DESTROY:
        return deserialize_asset_destroy_kernel(reader, subtype_name)
    if subtype == KernelSubtype.CONTRACT_CREATE:
        return deserialize_contract_create_kernel(reader, subtype_name)
    if subtype == KernelSubtype.CONTRACT_INVOKE:
        return deserialize_contract_invoke_kernel(reader, subtype_name)
    if subtype == KernelSubtype.EVM_INVOKE:
        return deserialize_evm_invoke_kernel(reader, subtype_name)

    raise DeserializationError(f"kernel subtype not implemented: {subtype_id}")


def deserialize_std_kernel(reader: BufferReader, subtype_name: str) -> dict[str, object]:
    """Deserialize a standard (``Std``) transaction kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label to embed in the result.

    Returns:
        Dictionary with ``subtype``, ``commitment``, ``signature``,
        ``fee``, ``min_height``, ``max_height``, ``nested_kernels``,
        ``can_embed``, and the optional keys ``hash_lock`` and
        ``relative_lock``.
    """
    flags = reader.read_u8()

    kernel: dict[str, object] = {
        "subtype": subtype_name,
        "commitment": reader.read_point_x(bool(flags & 1)),
        "signature": {
            "nonce_pub": reader.read_point_x(bool(flags & 0x10)),
            "k": reader.read_scalar(),
        },
    }

    kernel.update(deserialize_fee_height(reader, flags))

    if flags & 0x20:
        kernel["hash_lock"] = reader.read_hash32()

    kernel["nested_kernels"] = deserialize_nested_kernels(reader, flags)

    if flags & 0x80:
        flags2 = reader.read_u8()
        kernel["can_embed"] = bool(flags2 & 4)
        if flags2 & 2:
            kernel["relative_lock"] = {
                "kernel_id": reader.read_hash32(),
                "lock_height": reader.read_var_uint(),
            }
    else:
        kernel["can_embed"] = False

    return kernel


def deserialize_asset_emit_kernel(reader: BufferReader, subtype_name: str) -> dict[str, object]:
    """Deserialize an ``AssetEmit`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Asset-control base fields plus ``asset_id`` and ``value``.
    """
    kernel = deserialize_asset_control_base(reader, subtype_name)
    kernel["asset_id"] = reader.read_var_uint()
    kernel["value"] = reader.read_var_int()
    return kernel


def deserialize_asset_create_kernel(reader: BufferReader, subtype_name: str) -> dict[str, object]:
    """Deserialize an ``AssetCreate`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Asset-control base fields plus ``metadata_hex`` and, when the
        metadata is valid UTF-8, ``metadata_text``.
    """
    kernel = deserialize_asset_control_base(reader, subtype_name)
    metadata = reader.read_byte_buffer()
    kernel["metadata_hex"] = metadata.hex()
    text = decode_utf8(metadata)
    if text is not None:
        kernel["metadata_text"] = text
    return kernel


def deserialize_asset_destroy_kernel(reader: BufferReader, subtype_name: str) -> dict[str, object]:
    """Deserialize an ``AssetDestroy`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Asset-control base fields plus ``asset_id`` and ``deposit``.
    """
    kernel = deserialize_asset_control_base(reader, subtype_name)
    kernel["asset_id"] = reader.read_var_uint()
    kernel["deposit"] = reader.read_var_uint()
    return kernel


def deserialize_shielded_output_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    """Deserialize a ``ShieldedOutput`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Dictionary with ``subtype``, ``shielded_output``, fee/height
        fields, ``nested_kernels``, and ``can_embed``.
    """
    flags = reader.read_var_uint()
    kernel: dict[str, object] = {
        "subtype": subtype_name,
        "shielded_output": deserialize_shielded_txo(reader),
    }
    kernel.update(deserialize_fee_height(reader, flags))
    kernel["nested_kernels"] = deserialize_nested_kernels(reader, flags)
    kernel["can_embed"] = bool(flags & 0x80)
    return kernel


def deserialize_shielded_input_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    """Deserialize a ``ShieldedInput`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Dictionary with ``subtype``, ``window_end``, ``spend_proof``,
        fee/height fields, ``nested_kernels``, ``can_embed``, and optional
        ``asset_proof``.
    """
    flags = reader.read_var_uint()
    kernel: dict[str, object] = {
        "subtype": subtype_name,
        "window_end": reader.read_var_uint(),
        "spend_proof": deserialize_lelantus_proof(reader),
    }
    kernel.update(deserialize_fee_height(reader, flags))
    kernel["nested_kernels"] = deserialize_nested_kernels(reader, flags)
    kernel["can_embed"] = bool(flags & 0x80)
    if flags & 1:
        kernel["asset_proof"] = deserialize_asset_proof(reader)
    return kernel


def deserialize_contract_create_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    """Deserialize a ``ContractCreate`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Contract-control base fields plus ``data_hex`` (the contract bytecode).
    """
    kernel = deserialize_contract_control_base(reader, subtype_name)
    data = reader.read_byte_buffer()
    kernel["data_hex"] = data.hex()
    return kernel


def deserialize_contract_invoke_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    """Deserialize a ``ContractInvoke`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Contract-control base fields plus ``contract_id`` and ``method``.
    """
    kernel = deserialize_contract_control_base(reader, subtype_name)
    kernel["contract_id"] = reader.read_hash32()
    kernel["method"] = reader.read_var_uint()
    return kernel


def deserialize_evm_invoke_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    """Deserialize an ``EvmInvoke`` kernel.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Contract-control base fields plus ``from``, ``to``, ``nonce``,
        ``call_value``, and ``subsidy``.
    """
    kernel = deserialize_contract_control_base(reader, subtype_name)
    kernel["from"] = reader.read_fixed_hex(20)
    kernel["to"] = reader.read_fixed_hex(20)
    kernel["nonce"] = reader.read_var_uint()
    kernel["call_value"] = reader.read_fixed_hex(32)
    kernel["subsidy"] = reader.read_var_int()
    return kernel


def deserialize_asset_control_base(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    """Deserialize fields common to all asset-control kernels.

    Shared by ``AssetEmit``, ``AssetCreate``, and ``AssetDestroy``.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Dictionary with ``subtype``, ``commitment``, ``signature``,
        ``owner``, fee/height fields, ``nested_kernels``, and ``can_embed``.
    """
    flags = reader.read_var_uint()
    kernel: dict[str, object] = {
        "subtype": subtype_name,
        "commitment": reader.read_point_x(bool(flags & 1)),
        "signature": {
            "nonce_pub": reader.read_point_x(bool(flags & 0x10)),
            "k": reader.read_scalar(),
        },
        "owner": reader.read_hash32(),
    }
    kernel.update(deserialize_fee_height(reader, flags))
    kernel["nested_kernels"] = deserialize_nested_kernels(reader, flags)
    kernel["can_embed"] = bool(flags & 0x20)
    return kernel


def deserialize_contract_control_base(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    """Deserialize fields common to all contract-control kernels.

    Shared by ``ContractCreate``, ``ContractInvoke``, and ``EvmInvoke``.

    Args:
        reader: Buffer positioned immediately after the subtype byte.
        subtype_name: Human-readable subtype label.

    Returns:
        Dictionary with ``subtype``, ``commitment``, ``signature``,
        ``dependent``, ``can_embed``, ``args_hex``, fee/height fields,
        and ``nested_kernels``.
    """
    flags = reader.read_var_uint()
    kernel: dict[str, object] = {
        "subtype": subtype_name,
        "commitment": reader.read_point_x(bool(flags & 1)),
        "signature": {
            "nonce_pub": reader.read_point_x(bool(flags & 0x10)),
            "k": reader.read_scalar(),
        },
        "dependent": bool(flags & 0x80),
        "can_embed": bool(flags & 0x20),
    }
    args = reader.read_byte_buffer()
    kernel["args_hex"] = args.hex()
    kernel.update(deserialize_fee_height(reader, flags))
    kernel["nested_kernels"] = deserialize_nested_kernels(reader, flags)
    return kernel


def deserialize_fee_height(reader: BufferReader, flags: int) -> dict[str, object]:
    """Deserialize the optional fee and block-height fields from *flags*.

    Bit 1 – fee present, bit 2 – min_height present, bit 3 – max_height
    delta present (added to min_height).

    Args:
        reader: Buffer positioned at the start of the optional fee/height data.
        flags: Kernel flags byte that controls which fields are present.

    Returns:
        Dictionary with ``fee``, ``min_height``, and ``max_height``
        (``None`` when absent).
    """
    fee = reader.read_var_uint() if flags & 2 else 0
    min_height = reader.read_var_uint() if flags & 4 else 0
    max_height = min_height + reader.read_var_uint() if flags & 8 else None
    return {
        "fee": fee,
        "min_height": min_height,
        "max_height": max_height,
    }


def deserialize_nested_kernels(reader: BufferReader, flags: int) -> list[dict[str, object]]:
    """Deserialize the optional list of nested kernels from *flags*.

    Bit 6 of *flags* signals that nested kernels are present.  A leading
    zero count indicates mixed subtypes; otherwise all nested kernels are
    assumed to be ``Std``.

    Args:
        reader: Buffer positioned at the nested-kernels section.
        flags: Kernel flags value that controls whether this section exists.

    Returns:
        List of deserialized kernel dictionaries (empty if bit 6 is clear).
    """
    if not (flags & 0x40):
        return []

    count = reader.read_var_uint()
    mixed = count == 0
    if mixed:
        count = reader.read_var_uint()

    return [deserialize_kernel(reader, assume_std=not mixed) for _ in range(count)]


def deserialize_shielded_txo(reader: BufferReader) -> dict[str, object]:
    """Deserialize a shielded transaction output (Lelantus TXO).

    Args:
        reader: Buffer positioned at the start of the shielded TXO.

    Returns:
        Dictionary with ``commitment``, ``range_proof``, ``serial_pub``,
        ``signature``, and optional ``asset_proof``.
    """
    flags = reader.read_var_uint()
    commitment_x = reader.read_fixed_hex(32)
    range_proof = deserialize_confidential_range_proof(reader)
    serial_pub_x = reader.read_fixed_hex(32)
    nonce_pub = reader.read_point()
    txo: dict[str, object] = {
        "commitment": {
            "x": commitment_x,
            "y": bool(flags & 1),
        },
        "range_proof": range_proof,
        "serial_pub": {
            "x": serial_pub_x,
            "y": bool(flags & 2),
        },
        "signature": {
            "nonce_pub": {
                "x": nonce_pub["x"],
                "y": bool(flags & 4),
            },
            "k": [reader.read_scalar(), reader.read_scalar()],
        },
    }

    if flags & 8:
        txo["asset_proof"] = deserialize_asset_proof(reader)

    return txo


def deserialize_confidential_range_proof(reader: BufferReader) -> dict[str, object]:
    """Deserialize a Bulletproofs-style confidential range proof.

    Reads the Bulletproofs commitment points, scalars, inner-product rounds,
    and the packed Y-parity bits that follow.

    Args:
        reader: Buffer positioned at the start of the range proof.

    Returns:
        Dictionary with ``kind="confidential"`` plus all proof components.
    """
    a_x = reader.read_fixed_hex(32)
    s_x = reader.read_fixed_hex(32)
    t1_x = reader.read_fixed_hex(32)
    t2_x = reader.read_fixed_hex(32)
    tau_x = reader.read_scalar()
    mu = reader.read_scalar()
    t_dot = reader.read_scalar()

    lr_pairs = []
    for _ in range(INNER_PRODUCT_CYCLES):
        lr_pairs.append({
            "l": {"x": reader.read_fixed_hex(32), "y": False},
            "r": {"x": reader.read_fixed_hex(32), "y": False},
        })
    condensed = [reader.read_scalar(), reader.read_scalar()]

    bits = decode_lsb_bits(
        reader.read_bytes(((INNER_PRODUCT_CYCLES * 2 + 7) & ~7) // 8),
        INNER_PRODUCT_CYCLES * 2 + 4,
    )

    for index, pair in enumerate(lr_pairs):
        pair["l"]["y"] = bits[index * 2]
        pair["r"]["y"] = bits[index * 2 + 1]

    return {
        "kind": "confidential",
        "a": {"x": a_x, "y": bits[12]},
        "s": {"x": s_x, "y": bits[13]},
        "t1": {"x": t1_x, "y": bits[14]},
        "t2": {"x": t2_x, "y": bits[15]},
        "tau_x": tau_x,
        "mu": mu,
        "t_dot": t_dot,
        "inner_product": {
            "rounds": lr_pairs,
            "condensed": condensed,
        },
    }


def deserialize_public_range_proof(reader: BufferReader) -> dict[str, object]:
    """Deserialize a public (non-confidential) range proof.

    Args:
        reader: Buffer positioned at the start of the range proof.

    Returns:
        Dictionary with ``kind="public"``, ``value``, ``signature``, and
        ``recovery`` fields.
    """
    return {
        "kind": "public",
        "value": reader.read_var_uint(),
        "signature": {
            "nonce_pub": reader.read_point(),
            "k": reader.read_scalar(),
        },
        "recovery": {
            "idx": reader.read_big_uint(8),
            "type": reader.read_big_uint(4),
            "sub_idx": reader.read_big_uint(4),
            "checksum": reader.read_hash32(),
        },
    }


def deserialize_asset_proof(reader: BufferReader) -> dict[str, object]:
    """Deserialize an asset Sigma proof.

    Args:
        reader: Buffer positioned at the start of the asset proof.

    Returns:
        Dictionary with ``begin``, ``generator``, and ``sigma`` proof
        components.
    """
    cfg = SigmaConfig(n=ASSET_PROOF_N, M=ASSET_PROOF_M)
    begin = reader.read_var_uint()
    generator_x = reader.read_fixed_hex(32)
    sigma, extra_bits = deserialize_sigma_proof(
        reader,
        cfg,
        extra_bits=1,
    )
    return {
        "begin": begin,
        "generator": {
            "x": generator_x,
            "y": extra_bits[0],
        },
        "sigma": sigma,
    }


def deserialize_lelantus_proof(reader: BufferReader) -> dict[str, object]:
    """Deserialize a Lelantus spend proof.

    The proof dimensions (``n``, ``M``) are read from the buffer itself.

    Args:
        reader: Buffer positioned at the start of the Lelantus proof.

    Returns:
        Dictionary with ``cfg``, ``commitment``, ``spend_pk``,
        ``signature``, and ``sigma`` proof components.
    """
    cfg = SigmaConfig(
        n=reader.read_var_uint(),
        M=reader.read_var_uint(),
    )
    commitment_x = reader.read_fixed_hex(32)
    spend_pk_x = reader.read_fixed_hex(32)
    nonce_pub_x = reader.read_fixed_hex(32)
    p_k0 = reader.read_scalar()
    p_k1 = reader.read_scalar()
    sigma, extra_bits = deserialize_sigma_proof(reader, cfg, extra_bits=3)
    return {
        "cfg": {
            "n": cfg.n,
            "M": cfg.M,
            "N": pow(cfg.n, cfg.M),
            "f_count": cfg.f_count,
        },
        "commitment": {
            "x": commitment_x,
            "y": extra_bits[0],
        },
        "spend_pk": {
            "x": spend_pk_x,
            "y": extra_bits[1],
        },
        "signature": {
            "nonce_pub": {
                "x": nonce_pub_x,
                "y": extra_bits[2],
            },
            "k": [p_k0, p_k1],
        },
        "sigma": sigma,
    }


def deserialize_sigma_proof(
    reader: BufferReader,
    cfg: SigmaConfig,
    extra_bits: int,
) -> tuple[dict[str, object], list[bool]]:
    """Deserialize a generic one-out-of-N Sigma proof.

    Reads four commitment points (a, b, c, d), three scalars (z_a, z_c, z_r),
    ``cfg.M`` generator points, ``cfg.f_count`` f-scalars, and a packed
    bit-field that supplies Y-parities for all points plus *extra_bits*
    caller-specific bits.

    Args:
        reader: Buffer positioned at the start of the Sigma proof.
        cfg: Ring dimensions used to determine how many scalars/points to read.
        extra_bits: Additional bits to extract from the packed bit-field and
            return to the caller (used for outer Y-parity flags).

    Returns:
        A ``(proof_dict, extra_bit_list)`` pair where *extra_bit_list* has
        length *extra_bits*.
    """
    points = {
        "a": {"x": reader.read_fixed_hex(32), "y": False},
        "b": {"x": reader.read_fixed_hex(32), "y": False},
        "c": {"x": reader.read_fixed_hex(32), "y": False},
        "d": {"x": reader.read_fixed_hex(32), "y": False},
    }
    z_a = reader.read_scalar()
    z_c = reader.read_scalar()
    z_r = reader.read_scalar()
    g_points = [{"x": reader.read_fixed_hex(32), "y": False} for _ in range(cfg.M)]
    f_scalars = [reader.read_scalar() for _ in range(cfg.f_count)]

    bit_count = 4 + cfg.M + extra_bits
    bits = decode_msb_bits(reader.read_bytes((bit_count + 7) // 8), bit_count)

    points["a"]["y"] = bits[0]
    points["b"]["y"] = bits[1]
    points["c"]["y"] = bits[2]
    points["d"]["y"] = bits[3]

    for index, point in enumerate(g_points):
        point["y"] = bits[4 + index]

    return (
        {
            "cfg": {
                "n": cfg.n,
                "M": cfg.M,
                "N": pow(cfg.n, cfg.M),
                "f_count": cfg.f_count,
            },
            "part1": {
                "a": points["a"],
                "b": points["b"],
                "c": points["c"],
                "d": points["d"],
                "g_points": g_points,
            },
            "part2": {
                "z_a": z_a,
                "z_c": z_c,
                "z_r": z_r,
                "f_scalars": f_scalars,
            },
        },
        bits[4 + cfg.M :],
    )


def decode_msb_bits(data: bytes, bit_count: int) -> list[bool]:
    """Unpack *bit_count* bits from *data* in MSB-first order.

    Args:
        data: Raw bytes containing the packed bits.
        bit_count: Number of bits to extract.

    Returns:
        List of booleans, index 0 = most significant bit of ``data[0]``.
    """
    bits: list[bool] = []
    for index in range(bit_count):
        byte = data[index // 8]
        bits.append(bool((byte >> (7 - (index % 8))) & 1))
    return bits


def decode_lsb_bits(data: bytes, bit_count: int) -> list[bool]:
    """Unpack *bit_count* bits from *data* in LSB-first order.

    Args:
        data: Raw bytes containing the packed bits.
        bit_count: Number of bits to extract.

    Returns:
        List of booleans, index 0 = least significant bit of ``data[0]``.
    """
    bits: list[bool] = []
    for index in range(bit_count):
        byte = data[index // 8]
        bits.append(bool((byte >> (index % 8)) & 1))
    return bits


def decode_utf8(data: bytes) -> str | None:
    """Try to decode *data* as UTF-8.

    Args:
        data: Bytes to decode.

    Returns:
        Decoded string, or ``None`` if *data* is not valid UTF-8.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None