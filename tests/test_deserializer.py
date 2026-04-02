import json
import unittest
from pathlib import Path

from src.deserializer import (
    decode_lsb_bits,
    decode_msb_bits,
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


if __name__ == "__main__":
    unittest.main()