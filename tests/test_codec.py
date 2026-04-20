import pytest

from beam_p2p import (
    decode_transaction_id,
    decode_uint,
    encode_transaction_id,
    encode_uint,
    make_header,
    parse_header,
)
from beam_p2p import MessageType


@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 65_535, 1_000_000])
def test_encode_decode_uint_round_trip(value):
    encoded = encode_uint(value)
    decoded, size = decode_uint(encoded)
    assert decoded == value
    assert size == len(encoded)


def test_header_round_trip():
    header = make_header(MessageType.GET_TRANSACTION, 32)
    assert parse_header(header) == (MessageType.GET_TRANSACTION, 32)


def test_transaction_id_codec_requires_32_bytes():
    tx_id = bytes(range(32))
    assert decode_transaction_id(encode_transaction_id(tx_id)) == tx_id

    with pytest.raises(ValueError):
        encode_transaction_id(b"\x00")

    with pytest.raises(ValueError):
        decode_transaction_id(b"\x00")


def test_message_type_enum_interoperability():
    """Verify MessageType enum members work with codec and remain int-compatible."""
    # Verify enum member serializes and deserializes correctly
    msg_type = MessageType.STATUS
    header = make_header(msg_type, 42)
    parsed_type, size = parse_header(header)

    # Both enum member and raw int should be equal
    assert parsed_type == msg_type
    assert parsed_type == 0x44
    assert msg_type == 0x44
    assert size == 42