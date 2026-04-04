import struct

from .protocol import PROTO_MAGIC, MessageType


def encode_uint(value: int) -> bytes:
    if value < 128:
        return bytes([value | 0x80])

    size = 1
    while value >= (1 << (size * 8)):
        size += 1
    return bytes([size]) + value.to_bytes(size, "little")


def decode_uint(buf: bytes | bytearray, offset: int = 0) -> tuple[int, int]:
    size = buf[offset]
    if (size >> 7) & 1:
        return size & 0x7F, 1

    count = size & 0x7F
    return int.from_bytes(buf[offset + 1 : offset + 1 + count], "little"), 1 + count


def make_header(message_type: MessageType, size: int) -> bytes:
    header = bytearray(8)
    header[0:3] = PROTO_MAGIC
    header[3] = message_type
    struct.pack_into("<I", header, 4, size)
    return bytes(header)


def parse_header(header: bytes) -> tuple[MessageType, int]:
    if header[0:3] != PROTO_MAGIC:
        raise ValueError(f"bad protocol magic: {header[0:3].hex()}")

    return MessageType(header[3]), struct.unpack_from("<I", header, 4)[0]


def encode_transaction_id(tx_id: bytes) -> bytes:
    if len(tx_id) != 32:
        raise ValueError(f"transaction id must be 32 bytes, got {len(tx_id)}")
    return tx_id


def decode_transaction_id(payload: bytes | bytearray) -> bytes:
    if len(payload) != 32:
        raise ValueError(f"transaction id payload must be 32 bytes, got {len(payload)}")
    return bytes(payload)