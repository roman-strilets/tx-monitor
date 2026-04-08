import json
import pytest
from pathlib import Path

from src.deserializers import (
    BufferReader,
    DeserializationError,
    KernelSubtype,
    get_kernel_subtype_name,
    decode_lsb_bits,
    decode_msb_bits,
    deserialize_kernel,
    deserialize_new_transaction_payload,
)
from src.protocol_models import TxCounts


def test_decode_msb_bits():
    assert decode_msb_bits(bytes([0b10110000]), 4) == [True, False, True, True]


def test_decode_lsb_bits():
    assert decode_lsb_bits(bytes([0b00001101]), 4) == [True, False, True, True]


def test_parse_generated_capture_sample_when_available():
    sample_path = Path("mempool3.json")
    if not sample_path.exists():
        pytest.skip("mempool3.json is not available in this workspace")

    line = sample_path.read_text(encoding="utf-8").splitlines()[0]
    payload = bytes.fromhex(json.loads(line)["raw_payload_hex"])

    decoded = deserialize_new_transaction_payload(payload)

    assert decoded.transaction_present
    assert decoded.context is None
    assert decoded.fluff
    assert decoded.transaction.counts == TxCounts(
        inputs=2,
        outputs=2,
        kernels=1,
        kernels_mixed=False,
    )
    assert decoded.transaction.kernels[0].subtype == "Std"
    assert decoded.transaction.outputs[0].confidential_proof is not None
    assert decoded.transaction.outputs[0].asset_proof is not None


def test_kernel_subtype_enum_unsupported_code():
    """Verify that unsupported kernel subtype codes raise DeserializationError."""
    reader = BufferReader(bytes([255]))

    with pytest.raises(DeserializationError, match="unsupported kernel subtype: 255"):
        deserialize_kernel(reader, assume_std=False)


@pytest.mark.parametrize(
    "subtype,expected_name",
    [
        (KernelSubtype.STD, "Std"),
        (KernelSubtype.ASSET_EMIT, "AssetEmit"),
        (KernelSubtype.SHIELDED_OUTPUT, "ShieldedOutput"),
        (KernelSubtype.SHIELDED_INPUT, "ShieldedInput"),
        (KernelSubtype.ASSET_CREATE, "AssetCreate"),
        (KernelSubtype.ASSET_DESTROY, "AssetDestroy"),
        (KernelSubtype.CONTRACT_CREATE, "ContractCreate"),
        (KernelSubtype.CONTRACT_INVOKE, "ContractInvoke"),
        (KernelSubtype.EVM_INVOKE, "EvmInvoke"),
    ],
)
def test_kernel_subtype_display_names(subtype, expected_name):
    """Verify display name helper returns correct strings for all known subtypes."""
    assert get_kernel_subtype_name(subtype) == expected_name