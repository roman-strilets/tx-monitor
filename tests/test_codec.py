import unittest

from src.codec import (
    decode_transaction_id,
    decode_uint,
    encode_transaction_id,
    encode_uint,
    make_header,
    parse_header,
)
from src.protocol import MessageType


class CodecTests(unittest.TestCase):
    def test_encode_decode_uint_round_trip(self):
        for value in (0, 1, 127, 128, 255, 256, 65_535, 1_000_000):
            with self.subTest(value=value):
                encoded = encode_uint(value)
                decoded, size = decode_uint(encoded)
                self.assertEqual(decoded, value)
                self.assertEqual(size, len(encoded))

    def test_header_round_trip(self):
        header = make_header(MessageType.GET_TRANSACTION, 32)
        self.assertEqual(parse_header(header), (MessageType.GET_TRANSACTION, 32))

    def test_transaction_id_codec_requires_32_bytes(self):
        tx_id = bytes(range(32))
        self.assertEqual(decode_transaction_id(encode_transaction_id(tx_id)), tx_id)

        with self.assertRaises(ValueError):
            encode_transaction_id(b"\x00")

        with self.assertRaises(ValueError):
            decode_transaction_id(b"\x00")

    def test_message_type_enum_interoperability(self):
        """Verify MessageType enum members work with codec and remain int-compatible."""
        # Verify enum member serializes and deserializes correctly
        msg_type = MessageType.STATUS
        header = make_header(msg_type, 42)
        parsed_type, size = parse_header(header)
        
        # Both enum member and raw int should be equal
        self.assertEqual(parsed_type, msg_type)
        self.assertEqual(parsed_type, 0x44)
        self.assertEqual(msg_type, 0x44)
        self.assertEqual(size, 42)


if __name__ == "__main__":
    unittest.main()