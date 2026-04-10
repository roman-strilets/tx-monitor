"""Core helpers for the deserializer: reader, enums, and small utils.

This module holds the low-level BufferReader, the kernel-subtype enum,
and small bit/UTF-8 helpers used by the other split modules.
"""
from enum import IntEnum

from src.codec import decode_uint
from src.protocol_models import EcPoint


class KernelSubtype(IntEnum):
    """Beam protocol kernel subtype codes."""

    STD = 1
    ASSET_EMIT = 2
    SHIELDED_OUTPUT = 3
    SHIELDED_INPUT = 4
    ASSET_CREATE = 5
    ASSET_DESTROY = 6
    CONTRACT_CREATE = 7
    CONTRACT_INVOKE = 8
    EVM_INVOKE = 9


_KERNEL_SUBTYPE_NAMES = {
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


def get_kernel_subtype_name(subtype: KernelSubtype) -> str:
    """Return a human-readable name for a KernelSubtype.

    Args:
        subtype: KernelSubtype enum value.

    Returns:
        A short string name for the subtype, or "Unknown(<value>)" if
        the subtype is not in the mapping.
    """
    return _KERNEL_SUBTYPE_NAMES.get(subtype, f"Unknown({subtype})")


class DeserializationError(ValueError):
    """Raised when a transaction payload cannot be parsed."""


class BufferReader:
    """Cursor-based reader over an immutable bytes buffer.

    Provides typed read helpers (integers, booleans, fixed-width hex
    strings, elliptic-curve points) that advance an internal offset and
    raise :class:`DeserializationError` on underflow.
    """

    def __init__(self, data: bytes):
        """Create a new BufferReader.

        Args:
            data: The bytes buffer to read from.
        """
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        """Return the current read offset within the buffer."""
        return self._offset

    @property
    def remaining(self) -> int:
        """Return the number of unread bytes remaining in the buffer."""
        return len(self._data) - self._offset

    def read_bytes(self, size: int) -> bytes:
        """Read `size` bytes from the buffer and advance the cursor.

        Args:
            size: Number of bytes to read; must be non-negative.

        Returns:
            A bytes object of length `size`.

        Raises:
            DeserializationError: If `size` is negative or if the buffer
                does not contain enough bytes.
        """
        if size < 0:
            raise DeserializationError(f"negative read size: {size}")
        end = self._offset + size
        if end > len(self._data):
            raise DeserializationError(
                f"unexpected end of buffer at offset {self._offset}, need {size} bytes"
            )
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk

    def read_u8(self) -> int:
        """Read a single unsigned byte and return its integer value.

        Returns:
            The integer value in the range 0..255 represented by the
            single byte read from the buffer.

        Raises:
            DeserializationError: If there are no bytes left to read.
        """
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        """Read a single byte and interpret it as a boolean.

        The value is considered false only when the underlying byte is
        zero; any non-zero byte is interpreted as True.

        Returns:
            `False` if the byte read is 0, otherwise `True`.

        Raises:
            DeserializationError: If there are no bytes left to read.
        """
        return self.read_u8() != 0

    def read_var_uint(self) -> int:
        """Read a variable-length compact unsigned integer.

        Uses `decode_uint` from `src.codec` starting at the current
        offset. Advances the cursor by the number of bytes consumed.

        Returns:
            The decoded unsigned integer.

        Raises:
            DeserializationError: If the buffer ends unexpectedly while
                decoding the compact unsigned integer.
        """
        try:
            value, size = decode_uint(self._data, self._offset)
        except IndexError as exc:
            raise DeserializationError(
                f"unexpected end of compact unsigned integer at offset {self._offset}"
            ) from exc

        self._offset += size
        return value

    def read_var_int(self) -> int:
        """Read a variable-length signed integer.

        Encoding details:
        - The first (header) byte encodes sign and length information:
          - bit 7 (0x80): sign flag (1 = negative, 0 = positive)
          - bit 6 (0x40): one-byte flag (1 = value stored directly in low 6 bits)
          - bits 5..0 (0x3F): when one-byte flag is set, this is the
            absolute value (0..63). When the one-byte flag is clear,
            this field indicates the number of subsequent bytes that
            encode the absolute value in little-endian order.
        - If the one-byte flag is clear and the low-6 value is zero,
          the absolute value is 0 (no extra bytes are read).

        The method advances the internal cursor by the header and any
        value bytes that are read.

        Returns:
            The decoded signed integer (negative if the sign bit is set).

        Raises:
            DeserializationError: If the buffer ends unexpectedly while
                reading the header or the indicated value bytes.
        """
        head = self.read_u8()
        negative = (head >> 7) & 1
        one_byte = (head >> 6) & 1
        value = head & 0x3F

        if one_byte:
            return -value if negative else value

        raw = int.from_bytes(self.read_bytes(value), "little") if value else 0
        return -raw if negative else raw

    def read_big_uint(self, size: int) -> int:
        """Read a big-endian unsigned integer of `size` bytes.

        Args:
            size: Number of bytes to read.

        Returns:
            The integer value represented by the bytes.
        """
        return int.from_bytes(self.read_bytes(size), "big")

    def read_fixed_hex(self, size: int) -> str:
        """Read `size` bytes and return their hexadecimal representation.

        Args:
            size: Number of bytes to read from the buffer.

        Returns:
            A lowercase hexadecimal string representing the `size` bytes
            just read. The length of the returned string is `2 * size`.

        Raises:
            DeserializationError: If the buffer does not contain `size`
                bytes.
        """
        return self.read_bytes(size).hex()

    def read_scalar(self) -> str:
        """Read a 32-byte scalar and return it as a hex string.

        Returns:
            A 64-character lowercase hexadecimal string corresponding to
            the 32 bytes read from the buffer.

        Raises:
            DeserializationError: If the buffer does not contain 32 bytes.
        """
        return self.read_fixed_hex(32)

    def read_hash32(self) -> str:
        """Read a 32-byte hash and return it as a hex string.

        Returns:
            A 64-character lowercase hexadecimal string corresponding to
            the 32-byte hash read from the buffer.

        Raises:
            DeserializationError: If the buffer does not contain 32 bytes.
        """
        return self.read_fixed_hex(32)

    def read_point(self) -> EcPoint:
        """Read an elliptic-curve point encoded as an X coordinate and a Y flag.

        Format:
        - 32 bytes: X coordinate (big-endian raw bytes, returned as a
          64-character lowercase hex string).
        - 1 byte: boolean Y-parity flag (0 = False, non-zero = True).

        Returns:
            An `EcPoint` instance with `x` set to the hex string of the
            coordinate and `y` set to the boolean parity flag.

        Raises:
            DeserializationError: If the buffer does not contain the 33
                bytes required for the point encoding.
        """
        return EcPoint(x=self.read_fixed_hex(32), y=self.read_bool())

    def read_point_x(self, y_flag: bool) -> EcPoint:
        """Read a point X coordinate (32 bytes) and attach a provided Y flag.

        Args:
            y_flag: Boolean indicating the Y parity/flag to associate with
                the X coordinate that is read.

        Returns:
            An `EcPoint` with `x` set to the 64-character lowercase hex
            string read from the buffer and `y` set to `y_flag`.

        Raises:
            DeserializationError: If the buffer does not contain 32 bytes
                for the X coordinate.
        """
        return EcPoint(x=self.read_fixed_hex(32), y=y_flag)

    def read_byte_buffer(self) -> bytes:
        """Read a length-prefixed byte buffer.

        The buffer is encoded as a compact (variable-length) unsigned
        integer length followed by that many raw bytes.

        Returns:
            The raw bytes corresponding to the decoded length.

        Raises:
            DeserializationError: If the length prefix or the following
                bytes cannot be fully read from the buffer.
        """
        size = self.read_var_uint()
        return self.read_bytes(size)


def decode_msb_bits(data: bytes, bit_count: int) -> list[bool]:
    """Decode bits from `data` using most-significant-bit ordering.

    Args:
        data: Bytes containing the bitfield.
        bit_count: Number of bits to decode from the start of `data`.

    Returns:
        A list of booleans representing each decoded bit.
    """
    bits: list[bool] = []
    for index in range(bit_count):
        byte = data[index // 8]
        bits.append(bool((byte >> (7 - (index % 8))) & 1))
    return bits


def decode_lsb_bits(data: bytes, bit_count: int) -> list[bool]:
    """Decode bits from `data` using least-significant-bit ordering.

    Args:
        data: Bytes containing the bitfield.
        bit_count: Number of bits to decode from the start of `data`.

    Returns:
        A list of booleans representing each decoded bit.
    """
    bits: list[bool] = []
    for index in range(bit_count):
        byte = data[index // 8]
        bits.append(bool((byte >> (index % 8)) & 1))
    return bits


def decode_utf8(data: bytes) -> str | None:
    """Decode `data` as UTF-8, returning None on decode failure.

    Args:
        data: The bytes to decode.

    Returns:
        The decoded string on success, or `None` if decoding fails.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None
