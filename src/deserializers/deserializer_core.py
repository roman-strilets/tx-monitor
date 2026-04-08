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
        """Read a single unsigned byte and return its integer value."""
        return self.read_bytes(1)[0]

    def read_bool(self) -> bool:
        """Read a single byte and interpret it as a boolean.

        Returns:
            False if the byte is 0, True otherwise.
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

        The integer is encoded with a one-byte header where the top bits
        indicate sign and whether the value fits in a single byte.
        Advances the cursor by the consumed bytes.

        Returns:
            The decoded signed integer.
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
        """Read `size` bytes and return their hexadecimal representation."""
        return self.read_bytes(size).hex()

    def read_scalar(self) -> str:
        """Read a 32-byte scalar and return its hex string."""
        return self.read_fixed_hex(32)

    def read_hash32(self) -> str:
        """Read a 32-byte hash and return its hex string."""
        return self.read_fixed_hex(32)

    def read_point(self) -> EcPoint:
        """Read an elliptic-curve point stored as 32-byte x and a y flag.

        Returns:
            An `EcPoint` with `x` as a hex string and `y` as a boolean.
        """
        return EcPoint(x=self.read_fixed_hex(32), y=self.read_bool())

    def read_point_x(self, y_flag: bool) -> EcPoint:
        """Read a point x-coordinate (32 bytes) and set the given y flag.

        Args:
            y_flag: Boolean indicating the y parity/flag for the point.

        Returns:
            An `EcPoint` with the read x and provided y flag.
        """
        return EcPoint(x=self.read_fixed_hex(32), y=y_flag)

    def read_byte_buffer(self) -> bytes:
        """Read a length-prefixed byte buffer.

        First reads a compact unsigned integer length, then reads and
        returns that many bytes.

        Returns:
            The byte buffer of the decoded length.
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
