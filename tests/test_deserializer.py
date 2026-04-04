import json
import unittest
from pathlib import Path

from src.deserializer import (
    BufferReader,
    DeserializationError,
    KernelSubtype,
    _get_kernel_subtype_name,
    decode_lsb_bits,
    decode_msb_bits,
    deserialize_kernel,
    deserialize_new_transaction_payload,
)


class DeserializerTests(unittest.TestCase):
    def test_decode_msb_bits(self):
        self.assertEqual(
            decode_msb_bits(bytes([0b10110000]), 4),
            [True, False, True, True],
        )

    def test_decode_lsb_bits(self):
        self.assertEqual(
            decode_lsb_bits(bytes([0b00001101]), 4),
            [True, False, True, True],
        )

    def test_parse_generated_capture_sample_when_available(self):
        sample_path = Path("mempool3.json")
        if not sample_path.exists():
            self.skipTest("mempool3.json is not available in this workspace")

        line = sample_path.read_text(encoding="utf-8").splitlines()[0]
        payload = bytes.fromhex(json.loads(line)["raw_payload_hex"])

        decoded = deserialize_new_transaction_payload(payload)

        self.assertTrue(decoded["transaction_present"])
        self.assertIsNone(decoded["context"])
        self.assertTrue(decoded["fluff"])
        self.assertEqual(
            decoded["transaction"]["counts"],
            {
                "inputs": 2,
                "outputs": 2,
                "kernels": 1,
                "kernels_mixed": False,
            },
        )
        self.assertEqual(decoded["transaction"]["kernels"][0]["subtype"], "Std")
        self.assertIn("confidential_proof", decoded["transaction"]["outputs"][0])
        self.assertIn("asset_proof", decoded["transaction"]["outputs"][0])

    def test_kernel_subtype_enum_unsupported_code(self):
        """Verify that unsupported kernel subtype codes raise DeserializationError."""
        # Create a buffer with an invalid subtype code (255)
        reader = BufferReader(bytes([255]))
        
        with self.assertRaises(DeserializationError) as ctx:
            deserialize_kernel(reader, assume_std=False)
        
        self.assertIn("unsupported kernel subtype: 255", str(ctx.exception))

    def test_kernel_subtype_display_names(self):
        """Verify display name helper returns correct strings for all known subtypes."""
        expected_names = {
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
        
        for subtype, expected_name in expected_names.items():
            with self.subTest(subtype=subtype):
                self.assertEqual(_get_kernel_subtype_name(subtype), expected_name)


if __name__ == "__main__":
    unittest.main()