from dataclasses import dataclass

from .codec import decode_uint


ASSET_PROOF_N = 4
ASSET_PROOF_M = 3
INNER_PRODUCT_CYCLES = 6

KERNEL_SUBTYPES = {
    1: "Std",
    2: "AssetEmit",
    3: "ShieldedOutput",
    4: "ShieldedInput",
    5: "AssetCreate",
    6: "AssetDestroy",
    7: "ContractCreate",
    8: "ContractInvoke",
    9: "EvmInvoke",
}


class DeserializationError(ValueError):
    pass


@dataclass(frozen=True)
class SigmaConfig:
    n: int
    M: int

    @property
    def f_count(self) -> int:
        return self.M * (self.n - 1)


class BufferReader:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def read_bytes(self, size: int) -> bytes:
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
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        return self.read_u8() != 0

    def read_var_uint(self) -> int:
        try:
            value, size = decode_uint(self._data, self._offset)
        except IndexError as exc:
            raise DeserializationError(
                f"unexpected end of compact unsigned integer at offset {self._offset}"
            ) from exc

        self._offset += size
        return value

    def read_var_int(self) -> int:
        head = self.read_u8()
        negative = (head >> 7) & 1
        one_byte = (head >> 6) & 1
        value = head & 0x3F

        if one_byte:
            return -value if negative else value

        raw = int.from_bytes(self.read_bytes(value), "little") if value else 0
        return -raw if negative else raw

    def read_big_uint(self, size: int) -> int:
        return int.from_bytes(self.read_bytes(size), "big")

    def read_fixed_hex(self, size: int) -> str:
        return self.read_bytes(size).hex()

    def read_scalar(self) -> str:
        return self.read_fixed_hex(32)

    def read_hash32(self) -> str:
        return self.read_fixed_hex(32)

    def read_point(self) -> dict[str, object]:
        return {
            "x": self.read_fixed_hex(32),
            "y": self.read_bool(),
        }

    def read_point_x(self, y_flag: bool) -> dict[str, object]:
        return {
            "x": self.read_fixed_hex(32),
            "y": y_flag,
        }

    def read_byte_buffer(self) -> bytes:
        size = self.read_var_uint()
        return self.read_bytes(size)


def deserialize_new_transaction_payload(payload: bytes) -> dict[str, object]:
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
    flags = reader.read_u8()
    return {
        "commitment": reader.read_point_x(bool(flags & 1)),
    }


def deserialize_output(reader: BufferReader) -> dict[str, object]:
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
    subtype_id = 1 if assume_std else reader.read_u8()
    subtype_name = KERNEL_SUBTYPES.get(subtype_id)
    if subtype_name is None:
        raise DeserializationError(f"unsupported kernel subtype: {subtype_id}")

    if subtype_id == 1:
        return deserialize_std_kernel(reader, subtype_name)
    if subtype_id == 2:
        return deserialize_asset_emit_kernel(reader, subtype_name)
    if subtype_id == 3:
        return deserialize_shielded_output_kernel(reader, subtype_name)
    if subtype_id == 4:
        return deserialize_shielded_input_kernel(reader, subtype_name)
    if subtype_id == 5:
        return deserialize_asset_create_kernel(reader, subtype_name)
    if subtype_id == 6:
        return deserialize_asset_destroy_kernel(reader, subtype_name)
    if subtype_id == 7:
        return deserialize_contract_create_kernel(reader, subtype_name)
    if subtype_id == 8:
        return deserialize_contract_invoke_kernel(reader, subtype_name)
    if subtype_id == 9:
        return deserialize_evm_invoke_kernel(reader, subtype_name)

    raise DeserializationError(f"kernel subtype not implemented: {subtype_id}")


def deserialize_std_kernel(reader: BufferReader, subtype_name: str) -> dict[str, object]:
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
    kernel = deserialize_asset_control_base(reader, subtype_name)
    kernel["asset_id"] = reader.read_var_uint()
    kernel["value"] = reader.read_var_int()
    return kernel


def deserialize_asset_create_kernel(reader: BufferReader, subtype_name: str) -> dict[str, object]:
    kernel = deserialize_asset_control_base(reader, subtype_name)
    metadata = reader.read_byte_buffer()
    kernel["metadata_hex"] = metadata.hex()
    text = decode_utf8(metadata)
    if text is not None:
        kernel["metadata_text"] = text
    return kernel


def deserialize_asset_destroy_kernel(reader: BufferReader, subtype_name: str) -> dict[str, object]:
    kernel = deserialize_asset_control_base(reader, subtype_name)
    kernel["asset_id"] = reader.read_var_uint()
    kernel["deposit"] = reader.read_var_uint()
    return kernel


def deserialize_shielded_output_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
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
    kernel = deserialize_contract_control_base(reader, subtype_name)
    data = reader.read_byte_buffer()
    kernel["data_hex"] = data.hex()
    return kernel


def deserialize_contract_invoke_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
    kernel = deserialize_contract_control_base(reader, subtype_name)
    kernel["contract_id"] = reader.read_hash32()
    kernel["method"] = reader.read_var_uint()
    return kernel


def deserialize_evm_invoke_kernel(
    reader: BufferReader, subtype_name: str
) -> dict[str, object]:
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
    fee = reader.read_var_uint() if flags & 2 else 0
    min_height = reader.read_var_uint() if flags & 4 else 0
    max_height = min_height + reader.read_var_uint() if flags & 8 else None
    return {
        "fee": fee,
        "min_height": min_height,
        "max_height": max_height,
    }


def deserialize_nested_kernels(reader: BufferReader, flags: int) -> list[dict[str, object]]:
    if not (flags & 0x40):
        return []

    count = reader.read_var_uint()
    mixed = count == 0
    if mixed:
        count = reader.read_var_uint()

    return [deserialize_kernel(reader, assume_std=not mixed) for _ in range(count)]


def deserialize_shielded_txo(reader: BufferReader) -> dict[str, object]:
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
    bits: list[bool] = []
    for index in range(bit_count):
        byte = data[index // 8]
        bits.append(bool((byte >> (7 - (index % 8))) & 1))
    return bits


def decode_lsb_bits(data: bytes, bit_count: int) -> list[bool]:
    bits: list[bool] = []
    for index in range(bit_count):
        byte = data[index // 8]
        bits.append(bool((byte >> (index % 8)) & 1))
    return bits


def decode_utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None