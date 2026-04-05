"""Binary encoding and decoding helpers for the Beam wire protocol.

Implements Beam's variable-length unsigned-integer format and the 8-byte
message-frame header layout (3-byte magic + 1-byte type + 4-byte size).
"""
import struct

from .protocol import PROTO_MAGIC, MessageType


def encode_uint(value: int) -> bytes:
    """Encode *value* using Beam's variable-length unsigned-integer format.

    Values below 128 are encoded as a single byte with the high bit set.
    Larger values are prefixed with their byte-length (without the high bit),
    followed by the value in little-endian byte order.

    Args:
        value: Non-negative integer to encode.

    Returns:
        Encoded bytes.
    """
    if value < 128:
        return bytes([value | 0x80])

    size = 1
    while value >= (1 << (size * 8)):
        size += 1
    return bytes([size]) + value.to_bytes(size, "little")


def decode_uint(buf: bytes | bytearray, offset: int = 0) -> tuple[int, int]:
    """Decode a Beam variable-length unsigned integer from *buf* at *offset*.

    Args:
        buf: Buffer containing the encoded integer.
        offset: Byte offset within *buf* at which to start reading.

    Returns:
        A ``(value, bytes_consumed)`` pair.
    """
    size = buf[offset]
    if (size >> 7) & 1:
        return size & 0x7F, 1

    count = size & 0x7F
    return int.from_bytes(buf[offset + 1 : offset + 1 + count], "little"), 1 + count


def make_header(message_type: MessageType, size: int) -> bytes:
    """Build an 8-byte Beam message frame header.

    Layout: 3-byte protocol magic | 1-byte message type | 4-byte payload
    size (little-endian).

    Args:
        message_type: Type code of the message.
        size: Total byte-length of the payload that follows the header.

    Returns:
        8-byte header bytes.
    """
    header = bytearray(8)
    header[0:3] = PROTO_MAGIC
    header[3] = message_type
    struct.pack_into("<I", header, 4, size)
    return bytes(header)


def parse_header(header: bytes) -> tuple[MessageType, int]:
    """Parse an 8-byte Beam frame header.

    Args:
        header: Exactly 8 bytes as returned by a raw socket read.

    Returns:
        A ``(message_type, payload_size)`` pair.

    Raises:
        ValueError: If the protocol magic bytes do not match.
        ValueError: If the message-type byte is not a known :class:`MessageType`.
    """
    if header[0:3] != PROTO_MAGIC:
        raise ValueError(f"bad protocol magic: {header[0:3].hex()}")

    return MessageType(header[3]), struct.unpack_from("<I", header, 4)[0]


def encode_transaction_id(tx_id: bytes) -> bytes:
    """Validate and return the 32-byte transaction identifier as-is.

    Args:
        tx_id: Raw transaction ID bytes.

    Returns:
        The same 32-byte value.

    Raises:
        ValueError: If *tx_id* is not exactly 32 bytes.
    """
    if len(tx_id) != 32:
        raise ValueError(f"transaction id must be 32 bytes, got {len(tx_id)}")
    return tx_id


def decode_transaction_id(payload: bytes | bytearray) -> bytes:
    """Validate and return the 32-byte transaction ID from a raw message payload.

    Args:
        payload: Raw bytes of a HaveTransaction or GetTransaction message body.

    Returns:
        Immutable 32-byte transaction identifier.

    Raises:
        ValueError: If *payload* is not exactly 32 bytes.
    """
    if len(payload) != 32:
        raise ValueError(f"transaction id payload must be 32 bytes, got {len(payload)}")
    return bytes(payload)