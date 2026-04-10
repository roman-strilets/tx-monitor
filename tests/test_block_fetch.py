import pytest

from main import main
from src.codec import encode_get_body_pack_payload, encode_height_range, encode_uint
from src.connection import build_login_payload, parse_login_payload
from src.deserializers import (
    deserialize_body_pack_payload,
    deserialize_body_payload,
    deserialize_header_pack,
    deserialize_new_tip_payload,
)
from src.protocol import EXTENSION_VERSION
from src.utils import extension_bits


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def test_parse_login_payload_round_trips_build_login_payload():
    fork_hashes = [b"\x11" * 32, b"\x22" * 32]
    payload = build_login_payload(0x05, fork_hashes)

    decoded_hashes, decoded_flags = parse_login_payload(payload)

    assert decoded_hashes == fork_hashes
    assert decoded_flags == 0x05 | (extension_bits(EXTENSION_VERSION) << 4)


def test_encode_height_range_encodes_min_and_delta():
    assert encode_height_range(10, 13) == encode_uint(10) + encode_uint(3)


def test_encode_get_body_pack_payload_encodes_fields_in_order():
    top_hash = b"\xAA" * 32
    payload = encode_get_body_pack_payload(
        top_height=42,
        top_hash=top_hash,
        flag_perishable=2,
        flag_eternal=0,
        count_extra=7,
        block0=0,
        horizon_lo1=100,
        horizon_hi1=200,
    )

    assert payload == b"".join(
        (
            encode_uint(42),
            top_hash,
            b"\x02\x00",
            encode_uint(7),
            encode_uint(0),
            encode_uint(100),
            encode_uint(200),
        )
    )


def test_deserialize_header_pack_parses_single_header():
    payload = b"".join(
        (
            encode_uint(10),
            b"\x01" * 32,
            b"\x02" * 32,
            encode_uint(1),
            b"\x03" * 32,
            b"\x04" * 32,
            encode_uint(123456),
            b"\x05" * 104,
            encode_uint(0x123456),
            b"\x06" * 8,
        )
    )

    header = deserialize_header_pack(payload, [bytes([index]) * 32 for index in range(6)])

    assert header.height == 10
    assert header.previous_hash == ("01" * 32)
    assert header.chainwork == ("02" * 32)
    assert header.kernels == ("03" * 32)
    assert header.definition == ("04" * 32)
    assert header.timestamp == 123456
    assert header.pow_indices_hex == ("05" * 104)
    assert header.pow_nonce_hex == ("06" * 8)
    assert len(header.hash) == 64


def test_deserialize_new_tip_payload_parses_full_header():
    payload = b"".join(
        (
            encode_uint(12),
            b"\x01" * 32,
            b"\x02" * 32,
            b"\x03" * 32,
            b"\x04" * 32,
            encode_uint(999),
            b"\x05" * 104,
            encode_uint(0x654321),
            b"\x06" * 8,
        )
    )

    header = deserialize_new_tip_payload(payload, [bytes([index]) * 32 for index in range(6)])

    assert header.height == 12
    assert header.previous_hash == ("01" * 32)
    assert header.kernels == ("03" * 32)
    assert header.definition == ("04" * 32)
    assert header.timestamp == 999
    assert len(header.hash) == 64


def test_deserialize_new_tip_payload_accepts_suffix_login_hashes():
    payload = b"".join(
        (
            encode_uint(3810980),
            b"\x01" * 32,
            b"\x02" * 32,
            b"\x03" * 32,
            b"\x04" * 32,
            encode_uint(999),
            b"\x05" * 104,
            encode_uint(0x654321),
            b"\x06" * 8,
        )
    )

    header = deserialize_new_tip_payload(payload, [b"\xAA" * 32])

    assert header.rules_hash == ("aa" * 32)
    assert len(header.hash) == 64


def test_deserialize_body_payload_parses_full_outputs_and_kernels():
    header = deserialize_header_pack(
        b"".join(
            (
                encode_uint(10),
                b"\x01" * 32,
                b"\x02" * 32,
                encode_uint(1),
                b"\x03" * 32,
                b"\x04" * 32,
                encode_uint(9),
                b"\x05" * 104,
                encode_uint(0x123456),
                b"\x06" * 8,
            )
        ),
        [bytes([index]) * 32 for index in range(6)],
    )
    perishable = b"".join(
        (
            b"\x40" * 32,
            _u32(1),
            b"\x01",
            b"\x10" * 32,
            _u32(1),
            b"\x13",
            b"\x20" * 32,
            encode_uint(10),
        )
    )
    eternal = b"".join(
        (
            _u32(1),
            b"\x00",
            b"\x50" * 32,
            b"\x60" * 32,
            b"\x70" * 32,
        )
    )
    payload = encode_uint(len(perishable)) + perishable + encode_uint(len(eternal)) + eternal

    block = deserialize_body_payload(payload, header)

    assert block.counts.inputs == 1
    assert block.counts.outputs == 1
    assert block.counts.kernels == 1
    assert block.inputs[0].commitment.x == ("10" * 32)
    assert block.outputs[0].commitment.x == ("20" * 32)
    assert block.outputs[0].coinbase is True
    assert block.outputs[0].incubation == 10
    assert block.offset == ("40" * 32)
    assert block.outputs[0].recovery_only is False
    assert block.kernels[0].subtype == "Std"
    assert block.kernels[0].commitment.x == ("50" * 32)


def test_deserialize_body_payload_falls_back_to_recovery1_layout():
    header = deserialize_header_pack(
        b"".join(
            (
                encode_uint(10),
                b"\x01" * 32,
                b"\x02" * 32,
                encode_uint(1),
                b"\x03" * 32,
                b"\x04" * 32,
                encode_uint(9),
                b"\x05" * 104,
                encode_uint(0x123456),
                b"\x06" * 8,
            )
        ),
        [bytes([index]) * 32 for index in range(6)],
    )
    perishable = b"".join(
        (
            _u32(1),
            b"\x01",
            b"\x10" * 32,
            encode_uint(1),
            b"\x19",
            b"\x20" * 32,
            encode_uint(123),
            _u64(5),
            _u32(2),
            _u32(3),
            b"\x30" * 32,
            encode_uint(10),
            b"\x40" * 32,
        )
    )
    eternal = b"".join(
        (
            _u32(1),
            b"\x00",
            b"\x50" * 32,
            b"\x60" * 32,
            b"\x70" * 32,
        )
    )
    payload = encode_uint(len(perishable)) + perishable + encode_uint(len(eternal)) + eternal

    block = deserialize_body_payload(payload, header)

    assert block.counts.inputs == 1
    assert block.counts.outputs == 1
    assert block.outputs[0].recovery_only is True
    assert block.outputs[0].public_proof.value == 123
    assert block.offset == ("40" * 32)


def test_deserialize_body_pack_payload_uses_first_block_in_pack():
    header = deserialize_header_pack(
        b"".join(
            (
                encode_uint(10),
                b"\x01" * 32,
                b"\x02" * 32,
                encode_uint(1),
                b"\x03" * 32,
                b"\x04" * 32,
                encode_uint(9),
                b"\x05" * 104,
                encode_uint(0x123456),
                b"\x06" * 8,
            )
        ),
        [bytes([index]) * 32 for index in range(6)],
    )
    first_perishable = b"".join((b"\x41" * 32, _u32(0), _u32(0)))
    first_eternal = _u32(0)
    second_perishable = b"".join((b"\x99" * 32, _u32(0), _u32(0)))
    second_eternal = _u32(0)
    payload = b"".join(
        (
            encode_uint(2),
            encode_uint(len(first_perishable)),
            first_perishable,
            encode_uint(len(first_eternal)),
            first_eternal,
            encode_uint(len(second_perishable)),
            second_perishable,
            encode_uint(len(second_eternal)),
            second_eternal,
        )
    )

    block = deserialize_body_pack_payload(payload, header)

    assert block.offset == ("41" * 32)


def test_main_rejects_block_height_in_live_mode():
    with pytest.raises(SystemExit) as exc:
        main(["127.0.0.1", "--live", "--block-height", "10"])

    assert exc.value.code == 2