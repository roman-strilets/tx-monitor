"""Protocol-level data models for deserialised Beam transaction and block structures.

All models are immutable frozen dataclasses and together represent the full
parse tree produced by the deserializers package.
"""
from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Primitive / shared structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EcPoint:
    """Compressed elliptic-curve point."""

    x: str
    y: bool


@dataclass(frozen=True)
class KernelSignature:
    """Signature used in standard, asset-control, and contract kernels."""

    nonce_pub: EcPoint
    k: str


@dataclass(frozen=True)
class ShieldedSignature:
    """Signature used in shielded TXO and Lelantus proofs (two k-scalars)."""

    nonce_pub: EcPoint
    k: list[str]


@dataclass(frozen=True)
class RelativeLock:
    """Height lock relative to another kernel."""

    kernel_id: str
    lock_height: int


@dataclass(frozen=True)
class SigmaConfigInfo:
    """Ring dimensions for a Sigma / Lelantus proof."""

    n: int
    M: int
    N: int
    f_count: int


# ---------------------------------------------------------------------------
# Range proof structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LrPair:
    """One inner-product round (L, R point pair)."""

    left: EcPoint
    right: EcPoint


@dataclass(frozen=True)
class InnerProduct:
    """Bulletproofs inner-product argument."""

    rounds: list[LrPair]
    condensed: list[str]


@dataclass(frozen=True)
class ConfidentialRangeProof:
    """Bulletproofs-style confidential range proof."""

    kind: str
    a: EcPoint
    s: EcPoint
    t1: EcPoint
    t2: EcPoint
    tau_x: str
    mu: str
    t_dot: str
    inner_product: InnerProduct


@dataclass(frozen=True)
class Recovery:
    """Public range proof recovery metadata."""

    idx: int
    type: int
    sub_idx: int
    checksum: str


@dataclass(frozen=True)
class PublicRangeProof:
    """Non-confidential (public) range proof."""

    kind: str
    value: int
    signature: KernelSignature
    recovery: Recovery


# ---------------------------------------------------------------------------
# Sigma proof structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigmaPart1:
    """Commitment points of a one-out-of-N Sigma proof."""

    a: EcPoint
    b: EcPoint
    c: EcPoint
    d: EcPoint
    g_points: list[EcPoint]


@dataclass(frozen=True)
class SigmaPart2:
    """Scalars of a one-out-of-N Sigma proof."""

    z_a: str
    z_c: str
    z_r: str
    f_scalars: list[str]


@dataclass(frozen=True)
class SigmaProof:
    """One-out-of-N Sigma proof."""

    cfg: SigmaConfigInfo
    part1: SigmaPart1
    part2: SigmaPart2


@dataclass(frozen=True)
class AssetProof:
    """Asset-ownership Sigma proof."""

    begin: int
    generator: EcPoint
    sigma: SigmaProof


# ---------------------------------------------------------------------------
# Shielded / Lelantus structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShieldedTxo:
    """Shielded (Lelantus) transaction output."""

    commitment: EcPoint
    range_proof: ConfidentialRangeProof
    serial_pub: EcPoint
    signature: ShieldedSignature
    asset_proof: AssetProof | None


@dataclass(frozen=True)
class LelantusProof:
    """Lelantus spend proof."""

    cfg: SigmaConfigInfo
    commitment: EcPoint
    spend_pk: EcPoint
    signature: ShieldedSignature
    sigma: SigmaProof


# ---------------------------------------------------------------------------
# Transaction I/O structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TxInput:
    """Single transaction input."""

    commitment: EcPoint


@dataclass(frozen=True)
class TxOutput:
    """Single transaction output."""

    commitment: EcPoint
    coinbase: bool
    confidential_proof: ConfidentialRangeProof | None = None
    public_proof: PublicRangeProof | None = None
    incubation: int | None = None
    asset_proof: AssetProof | None = None
    extra_flags: int | None = None


@dataclass(frozen=True)
class RecoveryConfidentialRangeProof:
    """Recovery-only confidential range proof.

    Beam's ``Recovery1`` block-body format omits the inner-product proof,
    ``tau_x``, and ``t_dot`` fields. The remaining points and ``mu`` are still
    enough to represent what the node transmitted.
    """

    kind: str
    a: EcPoint
    s: EcPoint
    t1: EcPoint
    t2: EcPoint
    mu: str


@dataclass(frozen=True)
class RecoveryPublicRangeProof:
    """Recovery-only public range proof.

    Recovery-mode block bodies omit the public proof's signature while keeping
    the recovered value and key-derivation metadata.
    """

    kind: str
    value: int
    recovery: Recovery


@dataclass(frozen=True)
class RecoveryAssetProof:
    """Recovery-only asset proof payload."""

    generator: EcPoint


@dataclass(frozen=True)
class BlockOutput:
    """Single decoded block output."""

    commitment: EcPoint
    coinbase: bool
    recovery_only: bool
    confidential_proof: ConfidentialRangeProof | RecoveryConfidentialRangeProof | None = None
    public_proof: PublicRangeProof | RecoveryPublicRangeProof | None = None
    incubation: int | None = None
    asset_proof: AssetProof | RecoveryAssetProof | None = None
    extra_flags: int | None = None


@dataclass(frozen=True)
class TxCounts:
    """Transaction component counts."""

    inputs: int
    outputs: int
    kernels: int
    kernels_mixed: bool


# ---------------------------------------------------------------------------
# Kernel models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StdKernel:
    """Standard transaction kernel."""

    subtype: str
    commitment: EcPoint
    signature: KernelSignature
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    can_embed: bool
    hash_lock: str | None = None
    relative_lock: RelativeLock | None = None


@dataclass(frozen=True)
class AssetEmitKernel:
    """Asset-emission kernel."""

    subtype: str
    commitment: EcPoint
    signature: KernelSignature
    owner: str
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    can_embed: bool
    asset_id: int
    value: int


@dataclass(frozen=True)
class AssetCreateKernel:
    """Asset-creation kernel."""

    subtype: str
    commitment: EcPoint
    signature: KernelSignature
    owner: str
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    can_embed: bool
    metadata_hex: str
    metadata_text: str | None = None


@dataclass(frozen=True)
class AssetDestroyKernel:
    """Asset-destruction kernel."""

    subtype: str
    commitment: EcPoint
    signature: KernelSignature
    owner: str
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    can_embed: bool
    asset_id: int
    deposit: int


@dataclass(frozen=True)
class ShieldedOutputKernel:
    """Shielded-output kernel."""

    subtype: str
    shielded_output: ShieldedTxo
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    can_embed: bool


@dataclass(frozen=True)
class ShieldedInputKernel:
    """Shielded-input kernel."""

    subtype: str
    window_end: int
    spend_proof: LelantusProof
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    can_embed: bool
    asset_proof: AssetProof | None = None


@dataclass(frozen=True)
class ContractCreateKernel:
    """Contract-creation kernel."""

    subtype: str
    commitment: EcPoint
    signature: KernelSignature
    dependent: bool
    can_embed: bool
    args_hex: str
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    data_hex: str


@dataclass(frozen=True)
class ContractInvokeKernel:
    """Contract-invocation kernel."""

    subtype: str
    commitment: EcPoint
    signature: KernelSignature
    dependent: bool
    can_embed: bool
    args_hex: str
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    contract_id: str
    method: int


@dataclass(frozen=True)
class EvmInvokeKernel:
    """EVM-invocation kernel."""

    subtype: str
    commitment: EcPoint
    signature: KernelSignature
    dependent: bool
    can_embed: bool
    args_hex: str
    fee: int
    min_height: int
    max_height: int | None
    nested_kernels: list[Kernel]
    from_address: str
    to: str
    nonce: int
    call_value: str
    subsidy: int


#: Union of all kernel variant types.
Kernel = (
    StdKernel
    | AssetEmitKernel
    | AssetCreateKernel
    | AssetDestroyKernel
    | ShieldedOutputKernel
    | ShieldedInputKernel
    | ContractCreateKernel
    | ContractInvokeKernel
    | EvmInvokeKernel
)


@dataclass(frozen=True)
class BlockHeader:
    """Decoded Beam block header metadata."""

    height: int
    hash: str
    previous_hash: str
    chainwork: str
    kernels: str
    definition: str
    timestamp: int
    packed_difficulty: int
    difficulty: float
    rules_hash: str | None
    pow_indices_hex: str
    pow_nonce_hex: str


# ---------------------------------------------------------------------------
# Top-level structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Transaction:
    """A complete Beam transaction."""

    inputs: list[TxInput]
    outputs: list[TxOutput]
    kernels: list[Kernel]
    counts: TxCounts
    offset: str


@dataclass(frozen=True)
class NewTransactionPayload:
    """Parsed body of a Beam ``NewTransaction`` protocol message."""

    transaction_present: bool
    transaction: Transaction | None
    context: str | None
    fluff: bool


@dataclass(frozen=True)
class DecodedBlock:
    """Parsed Beam block returned by the block-fetch feature."""

    header: BlockHeader
    inputs: list[TxInput]
    outputs: list[BlockOutput]
    kernels: list[Kernel]
    counts: TxCounts
    offset: str | None = None
