import unittest

from src.codec import (
    decode_transaction_id,
    decode_uint,
    encode_transaction_id,
    encode_uint,
    make_header,
    parse_header,
)
from src.protocol import MSG_GET_TRANSACTION


class CodecTests(unittest.TestCase):
    def test_encode_decode_uint_round_trip(self):
        for value in (0, 1, 127, 128, 255, 256, 65_535, 1_000_000):
            with self.subTest(value=value):
                encoded = encode_uint(value)
                decoded, size = decode_uint(encoded)
                self.assertEqual(decoded, value)
                self.assertEqual(size, len(encoded))

    def test_header_round_trip(self):
        header = make_header(MSG_GET_TRANSACTION, 32)
        self.assertEqual(parse_header(header), (MSG_GET_TRANSACTION, 32))

    def test_transaction_id_codec_requires_32_bytes(self):
        tx_id = bytes(range(32))
        self.assertEqual(decode_transaction_id(encode_transaction_id(tx_id)), tx_id)

        with self.assertRaises(ValueError):
            encode_transaction_id(b"\x00")

        with self.assertRaises(ValueError):
            decode_transaction_id(b"\x00")


if __name__ == "__main__":
    unittest.main()