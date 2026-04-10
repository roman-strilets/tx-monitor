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

    The kernel payload begins (optionally) with a subtype identifier byte
    unless ``assume_std`` is True. This function reads the subtype (or
    assumes `STD`), validates it against :class:`KernelSubtype`, and calls
    the specific deserializer for that subtype.

    Args:
        reader: A :class:`BufferReader` positioned at the start of the
            kernel payload. The reader is used to read the subtype byte
            (unless ``assume_std``), and then the remaining kernel fields
            by the subtype-specific deserializer. The reader must provide
            methods such as ``read_u8()``, ``read_var_uint()``,
            ``read_point_x()``, ``read_hash32()``, and others used by the
            nested deserializers.
        assume_std: When True, the subtype byte is not consumed and the
            kernel is treated as a standard (`STD`) kernel. When False,
            the next byte in ``reader`` is interpreted as the subtype id.

    Returns:
        Kernel: An instance of the appropriate kernel model class (for
        example :class:`StdKernel`, :class:`AssetEmitKernel`, etc.).

    Raises:
        DeserializationError: If the subtype id is unsupported or if an
            underlying reader call fails to parse the expected data.
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

    The STD kernel format begins with a single flags byte that controls the
    presence and encoding of subsequent optional fields. After the flags,
    the function reads the kernel commitment, signature, optional fee and
    block-height constraints, any nested kernels, and optional locks.

    Args:
        reader: A :class:`BufferReader` positioned at the first byte of the
            STD kernel payload (the flags byte).
        subtype_name: A human-readable subtype name used to populate the
            ``subtype`` field of the returned :class:`StdKernel` model.

    Flags layout (bits):
        - 0x01: Passed as the ``compressed``/format hint to
                ``reader.read_point_x()`` when reading the commitment.
        - 0x02: Fee is present (handled by :func:`deserialize_fee_height`).
        - 0x04: Minimum height is present (handled by
                :func:`deserialize_fee_height`).
        - 0x08: Maximum height (stored as a delta) is present (handled by
                :func:`deserialize_fee_height`).
        - 0x10: Signature's nonce public point is encoded with the same
                ``read_point_x`` convention and is present.
        - 0x20: A 32-byte hash lock follows (read with ``read_hash32()``).
        - 0x40: Nested kernels are present and must be deserialized.
        - 0x80: An additional flags byte follows; that byte's bits
                indicate embedding capability and the presence of a
                relative lock:
                - 0x02 in the second flags byte: a ``RelativeLock`` entry follows.
                - 0x04 in the second flags byte: kernel may be embedded.

    Returns:
        StdKernel: A fully-populated standard kernel model.

    Raises:
        DeserializationError: If reader data is malformed or required
            fields cannot be read.
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
    """Deserialize an asset emission (ASSET_EMIT) kernel.

    The asset emission kernel reuses the shared asset-control base fields
    (commitment, signature, owner, fee/height constraints, and nested
    kernels) and then contains an ``asset_id`` and the emitted ``value``.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            asset emission payload (flags for the asset-control base).
        subtype_name: Human-readable subtype name used in the returned
            :class:`AssetEmitKernel`.

    Returns:
        AssetEmitKernel: The deserialized asset emission kernel.

    Raises:
        DeserializationError: If the reader fails to parse any of the
            required fields.
    """
    base = deserialize_asset_control_base(reader, subtype_name)
    return AssetEmitKernel(**base, asset_id=reader.read_var_uint(), value=reader.read_var_int())


def deserialize_asset_create_kernel(reader: BufferReader, subtype_name: str) -> AssetCreateKernel:
    """Deserialize an asset creation (ASSET_CREATE) kernel.

    Reads the shared asset-control base fields and then a metadata blob.
    The metadata blob is returned both as a hex string and attempted UTF-8
    decoded text (``metadata_text`` may be ``None`` if decoding fails).

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            asset creation payload.
        subtype_name: Human-readable subtype name for the resulting
            :class:`AssetCreateKernel`.

    Returns:
        AssetCreateKernel: Model with ``metadata_hex`` and
        ``metadata_text`` (decoded string or ``None``).

    Raises:
        DeserializationError: If the metadata blob cannot be read.
    """
    base = deserialize_asset_control_base(reader, subtype_name)
    metadata = reader.read_byte_buffer()
    from src.deserializers.deserializer_proofs import decode_utf8

    return AssetCreateKernel(**base, metadata_hex=metadata.hex(), metadata_text=decode_utf8(metadata))


def deserialize_asset_destroy_kernel(reader: BufferReader, subtype_name: str) -> AssetDestroyKernel:
    """Deserialize an asset destruction (ASSET_DESTROY) kernel.

    Parses the shared asset-control base fields and then reads the
    ``asset_id`` and ``deposit`` values associated with the destruction.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            asset-destroy payload.
        subtype_name: Human-readable subtype name for the resulting
            :class:`AssetDestroyKernel`.

    Returns:
        AssetDestroyKernel: The deserialized kernel model.

    Raises:
        DeserializationError: If expected fields are missing or malformed.
    """
    base = deserialize_asset_control_base(reader, subtype_name)
    return AssetDestroyKernel(**base, asset_id=reader.read_var_uint(), deposit=reader.read_var_uint())


def deserialize_shielded_output_kernel(
    reader: BufferReader, subtype_name: str
) -> ShieldedOutputKernel:
    """Deserialize a shielded output (SHIELDED_OUTPUT) kernel.

    The shielded output kernel contains a shielded transaction output
    (TXO) payload, fee/min/max block-height constraints, optional nested
    kernels, and an embedding-capable flag.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            shielded-output payload.
        subtype_name: Human-readable subtype name for the resulting
            :class:`ShieldedOutputKernel`.

    Returns:
        ShieldedOutputKernel: Model wrapping the deserialized shielded TXO
        and associated kernel metadata.

    Raises:
        DeserializationError: If inner TXO or proof parsing fails.
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
    """Deserialize a shielded input (SHIELDED_INPUT) kernel.

    The shielded input kernel includes LELANTUS spend proof data,
    a spending window (``window_end``), optional asset-proof information,
    fee and block-height constraints, nested kernels, and an embed flag.

    Args:
        reader: :class:`BufferReader` located at the start of the
            shielded-input payload.
        subtype_name: The readable subtype name to store in the returned
            :class:`ShieldedInputKernel`.

    Returns:
        ShieldedInputKernel: Model containing the spend proof and kernel
        metadata. The ``asset_proof`` field will be ``None`` if no asset
        proof was present (determined by flags).

    Raises:
        DeserializationError: If any required proof or field cannot be
            parsed.
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
    """Deserialize a contract creation (CONTRACT_CREATE) kernel.

    Reads the shared contract control base fields and then a byte buffer
    containing the contract initialization data. The binary initialization
    data is returned encoded as hexadecimal.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            contract-create payload.
        subtype_name: Human-readable subtype name for the resulting
            :class:`ContractCreateKernel`.

    Returns:
        ContractCreateKernel: Model containing contract metadata and
        ``data_hex`` (initialization payload encoded as hex).

    Raises:
        DeserializationError: If the data buffer cannot be read correctly.
    """
    base = deserialize_contract_control_base(reader, subtype_name)
    return ContractCreateKernel(**base, data_hex=reader.read_byte_buffer().hex())


def deserialize_contract_invoke_kernel(
    reader: BufferReader, subtype_name: str
) -> ContractInvokeKernel:
    """Deserialize a contract invocation (CONTRACT_INVOKE) kernel.

    After parsing the contract-control base, this function reads a 32-byte
    contract identifier and a variable-length unsigned integer indicating
    the method index to invoke.

    Args:
        reader: :class:`BufferReader` located at the start of the
            contract-invoke payload.
        subtype_name: Human-readable subtype name for the returned model.

    Returns:
        ContractInvokeKernel: Model populated with ``contract_id`` (32-byte
        hash) and the invoked ``method`` index.

    Raises:
        DeserializationError: On malformed contract id or method field.
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
    """Deserialize an EVM invocation (EVM_INVOKE) kernel.

    The EVM invoke kernel extends the contract-control base with EVM-specific
    fields: 20-byte origin and destination addresses, a variable-length
    nonce, a 32-byte call value, and a subsidy expressed as a variable-length
    signed integer.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            EVM-invoke payload.
        subtype_name: Human-readable subtype name for the returned
            :class:`EvmInvokeKernel`.

    Returns:
        EvmInvokeKernel: Model containing EVM invocation parameters such as
        ``from_address``, ``to``, ``nonce``, ``call_value``, and ``subsidy``.

    Raises:
        DeserializationError: If any EVM-specific field is malformed.
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
    """Parse shared fields common to asset-control kernels.

    Asset-control kernels (e.g., create/emit/destroy) share a common prefix
    consisting of flags, a commitment, signature, owner id, optional fee
    and height constraints, and nested kernels. This helper parses those
    shared fields and returns a mapping suitable for constructing the
    higher-level kernel model.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            asset-control payload (the flags varuint).
        subtype_name: Human-readable subtype name to include in the result.

    Returns:
        dict: A mapping with keys expected by the asset kernel models:
            ``subtype``, ``commitment``, ``signature``, ``owner``,
            ``fee``, ``min_height``, ``max_height``, ``nested_kernels``,
            and ``can_embed``.

    Raises:
        DeserializationError: If any required field cannot be read.
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
    """Parse shared fields common to contract-control kernels.

    Contract-control kernels contain flags, a commitment and signature,
    an arguments blob, optional fee/height constraints, and possibly nested
    kernels. This helper returns a dict of these parsed values for the
    contract-specific kernel constructors to consume.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            contract-control payload.
        subtype_name: Human-readable subtype name to include in the result.

    Returns:
        dict: Mapping with keys such as ``subtype``, ``commitment``,
        ``signature``, ``dependent`` (bool), ``can_embed`` (bool),
        ``args_hex`` (hex-encoded args), fee/height fields and
        ``nested_kernels``.

    Raises:
        DeserializationError: If parsing of the arguments or nested
            kernels fails.
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
    """Read optional fee and block-height constraint fields.

    The caller provides the previously-read ``flags`` value which encodes
    which of these optional fields are present. The values are returned
    as integers with sensible defaults when a field is absent.

    Flags:
        - 0x02: fee is present and encoded as a varuint immediately.
        - 0x04: min_height is present and encoded as a varuint.
        - 0x08: max_height is present but stored as a varuint delta from
                ``min_height``; the actual ``max_height`` returned is
                ``min_height + delta``.

    Args:
        reader: :class:`BufferReader` used to read the optional numeric fields.
        flags: Integer flags bitmask describing which fields are present.

    Returns:
        tuple[int, int, int|None]: ``(fee, min_height, max_height_or_None)``.
            If a field is not present, ``fee`` and ``min_height`` default to
            ``0`` and ``max_height`` is ``None``.
    """
    fee = reader.read_var_uint() if flags & 2 else 0
    min_height = reader.read_var_uint() if flags & 4 else 0
    max_height = min_height + reader.read_var_uint() if flags & 8 else None
    return fee, min_height, max_height


def deserialize_nested_kernels(reader: BufferReader, flags: int) -> list[Kernel]:
    """Deserialize nested kernels when present in a kernel payload.

    The presence of nested kernels is signalled by bit 0x40 in ``flags``.
    When nested kernels are present the encoding starts with a count:
      - If the count is non-zero, that many nested kernels follow and each
        nested kernel is encoded assuming the same subtype-format as the
        parent (``assume_std``).
      - If the count is zero, the nested list is "mixed": a subsequent
        varuint contains the actual count, and each nested kernel encodes
        its subtype explicitly, so deserialization must read the subtype
        for each nested kernel.

    Args:
        reader: :class:`BufferReader` positioned immediately after the flags
            (when the caller has indicated nested kernels may be present).
        flags: The flags value from the parent kernel that indicates whether
            nested kernels are present (bit 0x40).

    Returns:
        list[Kernel]: A list of deserialized nested kernel models.
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

    The shielded TXO contains a commitment (32-byte X coordinate), a
    confidential range proof, a serial public key (32-byte X), a nonce
    public point (full EC point), and a two-scalar signature. Optionally
    an asset proof may follow.

    Args:
        reader: :class:`BufferReader` positioned at the start of the
            shielded TXO payload (the flags varuint).

    Returns:
        ShieldedTxo: Model containing:
            - ``commitment``: :class:`EcPoint` built from the 32-byte X and a
               boolean indicating whether the full point encoding is used.
            - ``range_proof``: result of :func:`deserialize_confidential_range_proof`.
            - ``serial_pub``: :class:`EcPoint` for the serial public key.
            - ``signature``: :class:`ShieldedSignature` with nonce and scalars.
            - ``asset_proof``: Optional asset proof object or ``None``.

    Raises:
        DeserializationError: If any inner proof or point cannot be parsed.
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
