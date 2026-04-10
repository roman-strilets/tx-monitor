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
    RecoveryAssetProof,
    RecoveryConfidentialRangeProof,
    RecoveryPublicRangeProof,
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
    """Deserialize a confidential (Pedersen-style) range proof from the buffer.

    The encoded layout consumed from ``reader`` is:
      - Four 32-byte X-coordinates for points A, S, T1, T2 (read via ``read_fixed_hex(32)``).
      - Scalars ``tau_x``, ``mu``, and ``t_dot`` (each read with ``read_scalar()``).
      - ``INNER_PRODUCT_CYCLES`` inner-product rounds; each round contains a left
        and right 32-byte X-coordinate.
      - Two condensed scalars (read with ``read_scalar()`` twice).
      - A bitfield encoding the parity/format flags for all points:
        ``INNER_PRODUCT_CYCLES * 2`` bits for the inner-product points
        (left/right for each round) followed by four bits for A, S, T1, T2.
        The bitfield is read and decoded via ``decode_lsb_bits()``.

    The function reconstructs a :class:`ConfidentialRangeProof` where each
    curve point is represented as an :class:`EcPoint(x_hex, is_full_point)`
    using the corresponding parity bit from the decoded bitfield.

    Args:
        reader (BufferReader): Reader positioned at the start of the confidential range proof.

    Returns:
        ConfidentialRangeProof: Populated proof object with fields:
            - ``a``, ``s``, ``t1``, ``t2``: :class:`EcPoint` instances (X coordinate + parity).
            - ``tau_x``, ``mu``, ``t_dot``: scalar values.
            - ``inner_product``: :class:`InnerProduct` containing `rounds` (list of :class:`LrPair`)
              and ``condensed`` scalars.

    Raises:
        Any exceptions raised by :class:`BufferReader` if the input is truncated or malformed.
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
    """Deserialize a public (non-confidential) range proof payload.

    Reads a variable-length public ``value``, a kernel signature, and recovery
    information used to locate or validate the public output.

    Args:
        reader (BufferReader): Reader positioned at the start of a public range proof.

    Returns:
        PublicRangeProof: Object with attributes:
            - ``value`` (int): the publicly exposed value (read via ``read_var_uint()``).
            - ``signature`` (KernelSignature): contains ``nonce_pub`` (point) and ``k`` (scalar).
            - ``recovery`` (Recovery): recovery metadata with ``idx``, ``type``, ``sub_idx``, and ``checksum``.
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


def deserialize_recovery_confidential_range_proof(
    reader: BufferReader,
) -> RecoveryConfidentialRangeProof:
    """Deserialize a recovery-only confidential range proof.

    Beam's Recovery1 block-body encoding stores a compact recovery payload that
    contains only the X-coordinates of the four curve points (A, S, T1, T2),
    the ``mu`` scalar, and a single flags byte packing the parity bits for
    those points.

    Encoding read by this function:
      - Four 32-byte X-coordinates (A, S, T1, T2).
      - Scalar ``mu`` (read via ``read_scalar()``).
      - One ``u8`` flags byte: bit 0 -> A parity, bit 1 -> S parity,
        bit 2 -> T1 parity, bit 3 -> T2 parity.

    Args:
        reader (BufferReader): Reader positioned at the start of the recovery payload.

    Returns:
        RecoveryConfidentialRangeProof: Object with ``a``, ``s``, ``t1``, ``t2`` as :class:`EcPoint`
        instances built from the X-coordinates and parity bits, and ``mu`` scalar.

    Raises:
        Exceptions from :class:`BufferReader` for truncated or invalid input.
    """
    a_x = reader.read_fixed_hex(32)
    s_x = reader.read_fixed_hex(32)
    t1_x = reader.read_fixed_hex(32)
    t2_x = reader.read_fixed_hex(32)
    mu = reader.read_scalar()
    flags = reader.read_u8()

    return RecoveryConfidentialRangeProof(
        kind="confidential_recovery",
        a=EcPoint(a_x, bool(flags & 1)),
        s=EcPoint(s_x, bool(flags & 2)),
        t1=EcPoint(t1_x, bool(flags & 4)),
        t2=EcPoint(t2_x, bool(flags & 8)),
        mu=mu,
    )


def deserialize_recovery_public_range_proof(
    reader: BufferReader,
) -> RecoveryPublicRangeProof:
    """Deserialize a recovery-only public range proof.

    Reads the public ``value`` and a compact ``Recovery`` structure encoded
    as big-endian integers and a 32-byte checksum/hash.

    Args:
        reader (BufferReader): Reader positioned at the start of the recovery payload.

    Returns:
        RecoveryPublicRangeProof: Contains ``value`` (int) and ``recovery`` (Recovery).

    Raises:
        Exceptions from :class:`BufferReader` on read errors.
    """
    return RecoveryPublicRangeProof(
        kind="public_recovery",
        value=reader.read_var_uint(),
        recovery=Recovery(
            idx=reader.read_big_uint(8),
            type=reader.read_big_uint(4),
            sub_idx=reader.read_big_uint(4),
            checksum=reader.read_hash32(),
        ),
    )


def deserialize_recovery_asset_proof(reader: BufferReader) -> RecoveryAssetProof:
    """Deserialize the recovery-only asset proof payload.

    The recovery asset proof encoding contains a single EC point used as the
    asset generator. The point is read using the reader's point deserialization
    and returned wrapped in a :class:`RecoveryAssetProof`.

    Args:
        reader (BufferReader): Reader positioned at the start of the recovery asset payload.

    Returns:
        RecoveryAssetProof: Model with ``generator`` set to the parsed :class:`EcPoint`.

    Raises:
        Exceptions from :class:`BufferReader` on malformed input.
    """
    return RecoveryAssetProof(generator=reader.read_point())


def deserialize_asset_proof(reader: BufferReader) -> AssetProof:
    """Deserialize an asset proof used by asset-control kernels.

    Format:
      - ``begin`` (varuint): a starting index value associated with the proof.
      - ``generator`` X-coordinate (32 bytes).
      - A nested Sigma proof encoded with a fixed configuration
        (``n=ASSET_PROOF_N``, ``M=ASSET_PROOF_M``). The nested Sigma proof
        returns one extra boolean which encodes the generator parity.

    Args:
        reader (BufferReader): Reader positioned at the start of the asset proof.

    Returns:
        AssetProof: Model with fields:
            - ``begin`` (int)
            - ``generator`` (:class:`EcPoint`) constructed from the generator X
              coordinate and the extra parity bit returned by the Sigma proof.
            - ``sigma`` (:class:`SigmaProof`) the parsed nested Sigma proof.

    Raises:
        Exceptions raised by :func:`deserialize_sigma_proof` or the reader on malformed input.
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
    """Deserialize a Lelantus (shielded spend) proof.

    Encoding layout:
      - Two varuints defining the Sigma configuration: ``n`` and ``M``.
      - Three 32-byte X-coordinates: ``commitment``, ``spend_pk``, ``nonce_pub``.
      - Two signature scalars ``p_k0`` and ``p_k1``.
      - A nested Sigma proof; this function requests ``extra_bits=3`` from the
        Sigma parser so that parity flags for the three X-coordinates are
        returned alongside the proof.

    The returned :class:`LelantusProof` contains:
      - ``cfg``: :class:`SigmaConfigInfo` with `n`, `M`, `N` (n**M), and `f_count`.
      - ``commitment`` and ``spend_pk``: :class:`EcPoint` built using the parity bits.
      - ``signature``: :class:`ShieldedSignature` with ``nonce_pub`` (an :class:`EcPoint`)
         and two scalars ``k``.
      - ``sigma``: the nested :class:`SigmaProof`.

    Args:
        reader (BufferReader): Reader positioned at the start of the Lelantus proof.

    Returns:
        LelantusProof: Parsed Lelantus proof model as described above.

    Raises:
        Exceptions from :class:`BufferReader` or :func:`deserialize_sigma_proof` on malformed input.
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
    """Deserialize a Sigma proof and return the proof plus trailing boolean flags.

    Layout consumed from ``reader``:
      - Four 32-byte X-coordinates for points ``A``, ``B``, ``C``, ``D``.
      - Three scalars ``z_a``, ``z_c``, ``z_r``.
      - ``cfg.M`` 32-byte X-coordinates for the generator points ``g_points``.
      - ``cfg.f_count`` scalars for the proof's ``f`` vector.
      - A packed bitfield (MSB-ordered) of length ``4 + cfg.M + extra_bits``:
        - bits 0..3: parity flags for A, B, C, D respectively.
        - bits 4..(4+M-1): parity flags for each generator in ``g_points``.
        - the remaining ``extra_bits`` are returned to the caller as booleans
          and are not interpreted by the Sigma parser itself.

    Decoding notes:
      - The implementation reads the minimal number of bytes needed for the
        bitfield and decodes them with ``decode_msb_bits()`` so the caller
        receives a list of booleans in MSB-first order.

    Args:
        reader (BufferReader): Reader positioned at the start of the Sigma proof payload.
        cfg (SigmaConfig): Configuration describing the proof shape (`n` and `M`).
        extra_bits (int): Number of trailing boolean flags to extract and return.

    Returns:
        Tuple[SigmaProof, list[bool]]: A tuple where the first element is the parsed
        :class:`SigmaProof` and the second is the list of trailing boolean flags
        (length ``extra_bits``).

    Raises:
        Exceptions from :class:`BufferReader` on malformed or truncated input.
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
