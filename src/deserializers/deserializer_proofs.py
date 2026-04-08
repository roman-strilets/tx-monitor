"""Proof and range-proof deserializers extracted from the original module.
"""
from dataclasses import dataclass

from src.deserializers.deserializer_core import decode_lsb_bits, decode_msb_bits, BufferReader
from src.protocol_models import (
    AssetProof,
    ConfidentialRangeProof,
    InnerProduct,
    LrPair,
    PublicRangeProof,
    Recovery,
    LelantusProof,
    ShieldedSignature,
    SigmaConfigInfo,
    SigmaPart1,
    SigmaPart2,
    SigmaProof,
    EcPoint,
    KernelSignature,
)


ASSET_PROOF_N = 4
ASSET_PROOF_M = 3
INNER_PRODUCT_CYCLES = 6


@dataclass(frozen=True)
class SigmaConfig:
    """Configuration container for Sigma proofs.

    Attributes:
        n: Base branching factor (size of each group).
        M: Number of groups in the proof.
    """
    n: int
    M: int

    @property
    def f_count(self) -> int:
        """Number of `f` scalars expected in the proof.

        Calculated as M * (n - 1).
        """
        return self.M * (self.n - 1)


def deserialize_confidential_range_proof(reader: BufferReader) -> ConfidentialRangeProof:
    """Deserialize a confidential range proof from the buffer.

    Reads curve points, inner-product rounds, condensed scalars, and bit
    flags required to reconstruct a ConfidentialRangeProof model.

    Args:
        reader: BufferReader positioned at the start of a confidential range proof.

    Returns:
        ConfidentialRangeProof: Parsed confidential range proof instance.
    """
    a_x = reader.read_fixed_hex(32)
    s_x = reader.read_fixed_hex(32)
    t1_x = reader.read_fixed_hex(32)
    t2_x = reader.read_fixed_hex(32)
    tau_x = reader.read_scalar()
    mu = reader.read_scalar()
    t_dot = reader.read_scalar()

    lr_l_xs = []
    lr_r_xs = []
    for _ in range(INNER_PRODUCT_CYCLES):
        lr_l_xs.append(reader.read_fixed_hex(32))
        lr_r_xs.append(reader.read_fixed_hex(32))
    condensed = [reader.read_scalar(), reader.read_scalar()]

    bits = decode_lsb_bits(
        reader.read_bytes(((INNER_PRODUCT_CYCLES * 2 + 7) & ~7) // 8),
        INNER_PRODUCT_CYCLES * 2 + 4,
    )

    rounds = [
        LrPair(
            left=EcPoint(lr_l_xs[i], bits[i * 2]),
            right=EcPoint(lr_r_xs[i], bits[i * 2 + 1]),
        )
        for i in range(INNER_PRODUCT_CYCLES)
    ]

    return ConfidentialRangeProof(
        kind="confidential",
        a=EcPoint(a_x, bits[12]),
        s=EcPoint(s_x, bits[13]),
        t1=EcPoint(t1_x, bits[14]),
        t2=EcPoint(t2_x, bits[15]),
        tau_x=tau_x,
        mu=mu,
        t_dot=t_dot,
        inner_product=InnerProduct(rounds=rounds, condensed=condensed),
    )


def deserialize_public_range_proof(reader: BufferReader) -> PublicRangeProof:
    """Deserialize a public range proof payload.

    Reads the public value, kernel signature and recovery information.

    Args:
        reader: BufferReader positioned at the start of a public range proof.

    Returns:
        PublicRangeProof: Parsed public range proof.
    """
    return PublicRangeProof(
        kind="public",
        value=reader.read_var_uint(),
        signature=KernelSignature(
            nonce_pub=reader.read_point(),
            k=reader.read_scalar(),
        ),
        recovery=Recovery(
            idx=reader.read_big_uint(8),
            type=reader.read_big_uint(4),
            sub_idx=reader.read_big_uint(4),
            checksum=reader.read_hash32(),
        ),
    )


def deserialize_asset_proof(reader: BufferReader) -> AssetProof:
    """Deserialize an asset proof.

    Parses a fixed-format Sigma proof used for asset operations. This uses a
    fixed Sigma configuration (n=ASSET_PROOF_N, M=ASSET_PROOF_M).

    Args:
        reader: BufferReader positioned at the start of an asset proof.

    Returns:
        AssetProof: Parsed asset proof including generator and sigma proof.
    """
    cfg = SigmaConfig(n=ASSET_PROOF_N, M=ASSET_PROOF_M)
    begin = reader.read_var_uint()
    generator_x = reader.read_fixed_hex(32)
    sigma, extra_bits = deserialize_sigma_proof(reader, cfg, extra_bits=1)
    return AssetProof(
        begin=begin,
        generator=EcPoint(generator_x, extra_bits[0]),
        sigma=sigma,
    )


def deserialize_lelantus_proof(reader: BufferReader) -> LelantusProof:
    """Deserialize a LELANTUS spend proof.

    Reads the Sigma configuration, commitment, spend public key, nonce public,
    two signature scalars and the embedded Sigma proof.

    Args:
        reader: BufferReader positioned at the start of a LELANTUS proof.

    Returns:
        LelantusProof: Parsed LELANTUS proof structure.
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
    return LelantusProof(
        cfg=SigmaConfigInfo(n=cfg.n, M=cfg.M, N=pow(cfg.n, cfg.M), f_count=cfg.f_count),
        commitment=EcPoint(commitment_x, extra_bits[0]),
        spend_pk=EcPoint(spend_pk_x, extra_bits[1]),
        signature=ShieldedSignature(
            nonce_pub=EcPoint(nonce_pub_x, extra_bits[2]),
            k=[p_k0, p_k1],
        ),
        sigma=sigma,
    )


def deserialize_sigma_proof(
    reader: BufferReader,
    cfg: SigmaConfig,
    extra_bits: int,
) -> tuple[SigmaProof, list[bool]]:
    """Deserialize a Sigma proof and return the proof and extra bit flags.

    Reads the A/B/C/D curve points, z-scalars, generator points, the `f`
    scalars and the MSB-encoded bit flags. Returns a tuple of the constructed
    SigmaProof model and the list of extra boolean flags that follow the core
    per-point flags.

    Args:
        reader: BufferReader positioned at the start of the sigma proof.
        cfg: SigmaConfig describing proof dimensions (`n` and `M`).
        extra_bits: Number of extra boolean bits to extract after core flags.

    Returns:
        Tuple[ SigmaProof, list[bool] ]: The parsed SigmaProof and remaining booleans.
    """
    a_x = reader.read_fixed_hex(32)
    b_x = reader.read_fixed_hex(32)
    c_x = reader.read_fixed_hex(32)
    d_x = reader.read_fixed_hex(32)
    z_a = reader.read_scalar()
    z_c = reader.read_scalar()
    z_r = reader.read_scalar()
    g_xs = [reader.read_fixed_hex(32) for _ in range(cfg.M)]
    f_scalars = [reader.read_scalar() for _ in range(cfg.f_count)]

    bit_count = 4 + cfg.M + extra_bits
    bits = decode_msb_bits(reader.read_bytes((bit_count + 7) // 8), bit_count)

    return (
        SigmaProof(
            cfg=SigmaConfigInfo(n=cfg.n, M=cfg.M, N=pow(cfg.n, cfg.M), f_count=cfg.f_count),
            part1=SigmaPart1(
                a=EcPoint(a_x, bits[0]),
                b=EcPoint(b_x, bits[1]),
                c=EcPoint(c_x, bits[2]),
                d=EcPoint(d_x, bits[3]),
                g_points=[EcPoint(g_xs[i], bits[4 + i]) for i in range(cfg.M)],
            ),
            part2=SigmaPart2(
                z_a=z_a,
                z_c=z_c,
                z_r=z_r,
                f_scalars=f_scalars,
            ),
        ),
        bits[4 + cfg.M :],
    )
