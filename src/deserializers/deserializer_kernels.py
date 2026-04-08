"""Kernel-related deserializers extracted from the original module.
"""
from src.deserializers.deserializer_core import (
    BufferReader,
    KernelSubtype,
    get_kernel_subtype_name,
    DeserializationError,
)
from src.deserializers.deserializer_proofs import (
    deserialize_confidential_range_proof,
    deserialize_asset_proof,
    deserialize_lelantus_proof,
)
from src.protocol_models import (
    AssetCreateKernel,
    AssetDestroyKernel,
    AssetEmitKernel,
    ContractCreateKernel,
    ContractInvokeKernel,
    EvmInvokeKernel,
    EcPoint,
    Kernel,
    KernelSignature,
    RelativeLock,
    ShieldedOutputKernel,
    ShieldedInputKernel,
    ShieldedSignature,
    ShieldedTxo,
    StdKernel,
)


def deserialize_kernel(reader: BufferReader, assume_std: bool) -> Kernel:
    """Deserialize a kernel and dispatch to the appropriate handler.

    If ``assume_std`` is True, the kernel subtype is assumed to be STD
    and the subtype byte is not read from the stream. Otherwise the
    subtype id is read from ``reader``. The function raises
    ``DeserializationError`` for unsupported subtypes.

    Args:
        reader: BufferReader positioned at the kernel payload.
        assume_std: If True, treat the kernel as a standard kernel.

    Returns:
        Kernel: A deserialized kernel instance.
    """
    subtype_id = 1 if assume_std else reader.read_u8()

    try:
        subtype = KernelSubtype(subtype_id)
    except ValueError:
        raise DeserializationError(f"unsupported kernel subtype: {subtype_id}")

    subtype_name = get_kernel_subtype_name(subtype)

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


def deserialize_std_kernel(reader: BufferReader, subtype_name: str) -> StdKernel:
    """Deserialize a standard (STD) kernel.

    Reads flags, commitment, signature, optional fee/height fields,
    nested kernels, optional hash lock, and optional relative lock.

    Args:
        reader: BufferReader positioned at the start of the STD kernel.
        subtype_name: Human-readable subtype name for the resulting model.

    Returns:
        StdKernel: The deserialized standard kernel object.
    """
    flags = reader.read_u8()
    commitment = reader.read_point_x(bool(flags & 1))
    signature = KernelSignature(
        nonce_pub=reader.read_point_x(bool(flags & 0x10)),
        k=reader.read_scalar(),
    )
    fee, min_height, max_height = deserialize_fee_height(reader, flags)
    hash_lock = reader.read_hash32() if flags & 0x20 else None
    nested_kernels = deserialize_nested_kernels(reader, flags)
    can_embed = False
    relative_lock = None
    if flags & 0x80:
        flags2 = reader.read_u8()
        can_embed = bool(flags2 & 4)
        if flags2 & 2:
            relative_lock = RelativeLock(
                kernel_id=reader.read_hash32(),
                lock_height=reader.read_var_uint(),
            )
    return StdKernel(
        subtype=subtype_name,
        commitment=commitment,
        signature=signature,
        fee=fee,
        min_height=min_height,
        max_height=max_height,
        nested_kernels=nested_kernels,
        can_embed=can_embed,
        hash_lock=hash_lock,
        relative_lock=relative_lock,
    )


def deserialize_asset_emit_kernel(reader: BufferReader, subtype_name: str) -> AssetEmitKernel:
    """Deserialize an asset emission kernel.

    Parses the shared asset-control base fields then reads the
    ``asset_id`` and emitted ``value``.

    Returns:
        AssetEmitKernel: Deserialized asset emit kernel.
    """
    base = deserialize_asset_control_base(reader, subtype_name)
    return AssetEmitKernel(**base, asset_id=reader.read_var_uint(), value=reader.read_var_int())


def deserialize_asset_create_kernel(reader: BufferReader, subtype_name: str) -> AssetCreateKernel:
    """Deserialize an asset creation kernel.

    Reads the common asset-control base fields and the metadata blob.
    Returns both the hex representation and the UTF-8 decoded text
    (when decodable).

    Returns:
        AssetCreateKernel
    """
    base = deserialize_asset_control_base(reader, subtype_name)
    metadata = reader.read_byte_buffer()
    from src.deserializers.deserializer_proofs import decode_utf8

    return AssetCreateKernel(**base, metadata_hex=metadata.hex(), metadata_text=decode_utf8(metadata))


def deserialize_asset_destroy_kernel(reader: BufferReader, subtype_name: str) -> AssetDestroyKernel:
    """Deserialize an asset destruction kernel.

    Parses the asset-control base and reads ``asset_id`` and ``deposit``.

    Returns:
        AssetDestroyKernel
    """
    base = deserialize_asset_control_base(reader, subtype_name)
    return AssetDestroyKernel(**base, asset_id=reader.read_var_uint(), deposit=reader.read_var_uint())


def deserialize_shielded_output_kernel(
    reader: BufferReader, subtype_name: str
) -> ShieldedOutputKernel:
    """Deserialize a shielded output kernel.

    Reads the shielded TXO payload, fee/height constraints, nested kernels,
    and embedding flag.

    Returns:
        ShieldedOutputKernel
    """
    flags = reader.read_var_uint()
    shielded_output = deserialize_shielded_txo(reader)
    fee, min_height, max_height = deserialize_fee_height(reader, flags)
    nested_kernels = deserialize_nested_kernels(reader, flags)
    return ShieldedOutputKernel(
        subtype=subtype_name,
        shielded_output=shielded_output,
        fee=fee,
        min_height=min_height,
        max_height=max_height,
        nested_kernels=nested_kernels,
        can_embed=bool(flags & 0x80),
    )


def deserialize_shielded_input_kernel(
    reader: BufferReader, subtype_name: str
) -> ShieldedInputKernel:
    """Deserialize a shielded input kernel.

    Reads flags, window end, the LELANTUS spend proof, optional asset
    proof, fee/height fields, nested kernels, and embedding flag.

    Returns:
        ShieldedInputKernel
    """
    flags = reader.read_var_uint()
    window_end = reader.read_var_uint()
    spend_proof = deserialize_lelantus_proof(reader)
    fee, min_height, max_height = deserialize_fee_height(reader, flags)
    nested_kernels = deserialize_nested_kernels(reader, flags)
    return ShieldedInputKernel(
        subtype=subtype_name,
        window_end=window_end,
        spend_proof=spend_proof,
        fee=fee,
        min_height=min_height,
        max_height=max_height,
        nested_kernels=nested_kernels,
        can_embed=bool(flags & 0x80),
        asset_proof=deserialize_asset_proof(reader) if flags & 1 else None,
    )


def deserialize_contract_create_kernel(
    reader: BufferReader, subtype_name: str
) -> ContractCreateKernel:
    """Deserialize a contract creation kernel.

    Parses contract-control base fields and returns the contract initialization
    ``data`` as a hex string.

    Returns:
        ContractCreateKernel
    """
    base = deserialize_contract_control_base(reader, subtype_name)
    return ContractCreateKernel(**base, data_hex=reader.read_byte_buffer().hex())


def deserialize_contract_invoke_kernel(
    reader: BufferReader, subtype_name: str
) -> ContractInvokeKernel:
    """Deserialize a contract invocation kernel.

    Reads the contract-control base and then the target ``contract_id`` and
    invocation ``method`` index.

    Returns:
        ContractInvokeKernel
    """
    base = deserialize_contract_control_base(reader, subtype_name)
    return ContractInvokeKernel(
        **base,
        contract_id=reader.read_hash32(),
        method=reader.read_var_uint(),
    )


def deserialize_evm_invoke_kernel(
    reader: BufferReader, subtype_name: str
) -> EvmInvokeKernel:
    """Deserialize an EVM invocation kernel.

    Parses the contract-control base then reads EVM-specific fields such as
    addresses, nonce, call value and subsidy.

    Returns:
        EvmInvokeKernel
    """
    base = deserialize_contract_control_base(reader, subtype_name)
    return EvmInvokeKernel(
        **base,
        from_address=reader.read_fixed_hex(20),
        to=reader.read_fixed_hex(20),
        nonce=reader.read_var_uint(),
        call_value=reader.read_fixed_hex(32),
        subsidy=reader.read_var_int(),
    )


def deserialize_asset_control_base(
    reader: BufferReader, subtype_name: str
) -> dict:
    """Parse shared fields for asset-control kernels.

    Returns a mapping of values needed to construct asset kernel models,
    including commitment, signature, owner, fee/height fields and nested
    kernels.
    """
    flags = reader.read_var_uint()
    commitment = reader.read_point_x(bool(flags & 1))
    signature = KernelSignature(
        nonce_pub=reader.read_point_x(bool(flags & 0x10)),
        k=reader.read_scalar(),
    )
    owner = reader.read_hash32()
    fee, min_height, max_height = deserialize_fee_height(reader, flags)
    nested_kernels = deserialize_nested_kernels(reader, flags)
    return {
        "subtype": subtype_name,
        "commitment": commitment,
        "signature": signature,
        "owner": owner,
        "fee": fee,
        "min_height": min_height,
        "max_height": max_height,
        "nested_kernels": nested_kernels,
        "can_embed": bool(flags & 0x20),
    }


def deserialize_contract_control_base(
    reader: BufferReader, subtype_name: str
) -> dict:
    """Parse shared fields for contract-control kernels.

    Returns a mapping used to construct contract-related kernel models,
    including arguments, dependency and embedding flags, and fee/height
    information.
    """
    flags = reader.read_var_uint()
    commitment = reader.read_point_x(bool(flags & 1))
    signature = KernelSignature(
        nonce_pub=reader.read_point_x(bool(flags & 0x10)),
        k=reader.read_scalar(),
    )
    args = reader.read_byte_buffer()
    fee, min_height, max_height = deserialize_fee_height(reader, flags)
    nested_kernels = deserialize_nested_kernels(reader, flags)
    return {
        "subtype": subtype_name,
        "commitment": commitment,
        "signature": signature,
        "dependent": bool(flags & 0x80),
        "can_embed": bool(flags & 0x20),
        "args_hex": args.hex(),
        "fee": fee,
        "min_height": min_height,
        "max_height": max_height,
        "nested_kernels": nested_kernels,
    }


def deserialize_fee_height(reader: BufferReader, flags: int) -> tuple[int, int, int | None]:
    """Read optional fee and block-height constraints.

    Bits in ``flags`` determine which fields are present:
      - 0x2: fee is present
      - 0x4: min_height is present
      - 0x8: max_height is present and stored as a delta from min_height

    Returns:
        A tuple of (fee, min_height, max_height_or_None).
    """
    fee = reader.read_var_uint() if flags & 2 else 0
    min_height = reader.read_var_uint() if flags & 4 else 0
    max_height = min_height + reader.read_var_uint() if flags & 8 else None
    return fee, min_height, max_height


def deserialize_nested_kernels(reader: BufferReader, flags: int) -> list[Kernel]:
    """Deserialize nested kernels when present.

    If the nested-kernels bit (0x40) is not set an empty list is returned.
    If the count is zero the nested list is mixed and each nested kernel
    encodes its subtype explicitly.
    """
    if not (flags & 0x40):
        return []

    count = reader.read_var_uint()
    mixed = count == 0
    if mixed:
        count = reader.read_var_uint()

    return [deserialize_kernel(reader, assume_std=not mixed) for _ in range(count)]


def deserialize_shielded_txo(reader: BufferReader) -> ShieldedTxo:
    """Deserialize a shielded transaction output (ShieldedTxo).

    Reads commitment, confidential range proof, serial public key, nonce
    public point, signature scalars, and an optional asset proof flag.

    Returns:
        ShieldedTxo
    """
    flags = reader.read_var_uint()
    commitment_x = reader.read_fixed_hex(32)
    range_proof = deserialize_confidential_range_proof(reader)
    serial_pub_x = reader.read_fixed_hex(32)
    nonce_pub_point = reader.read_point()
    return ShieldedTxo(
        commitment=EcPoint(commitment_x, bool(flags & 1)),
        range_proof=range_proof,
        serial_pub=EcPoint(serial_pub_x, bool(flags & 2)),
        signature=ShieldedSignature(
            nonce_pub=EcPoint(nonce_pub_point.x, bool(flags & 4)),
            k=[reader.read_scalar(), reader.read_scalar()],
        ),
        asset_proof=deserialize_asset_proof(reader) if flags & 8 else None,
    )
