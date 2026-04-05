"""Utility helpers shared across the Beam monitor package.

Provides address formatting and parsing, fork-hash validation, Beam
extension-version bit encoding, and ISO-8601 timestamp generation.
"""
from datetime import datetime, timezone

from .protocol import Address


def format_address(address: Address) -> str:
    """Format a ``(host, port)`` address as ``"host:port"``.

    Args:
        address: ``(host, port)`` tuple.

    Returns:
        Human-readable address string.
    """
    return f"{address[0]}:{address[1]}"


def parse_endpoint(value: str, default_port: int) -> Address:
    """Parse a node address string into a ``(host, port)`` tuple.

    Accepts either ``"host"`` (port defaults to *default_port*) or
    ``"host:port"`` forms.

    Args:
        value: Raw address string supplied by the user.
        default_port: Port to use when *value* contains no explicit port.

    Returns:
        ``(host, port)`` tuple.

    Raises:
        ValueError: If the address is malformed or the port is out of range.
    """
    host = value
    port = default_port
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        if not host:
            raise ValueError(f"invalid address: {value!r}")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"invalid port in address: {value!r}") from exc

    if not 0 < port < 65536:
        raise ValueError(f"port out of range in address: {value!r}")

    return host, port


def parse_fork_hashes(values: list[str]) -> list[bytes]:
    """Decode and validate a list of hex-encoded fork-configuration hashes.

    Args:
        values: List of 64-character hex strings, one per fork hash.

    Returns:
        List of 32-byte values in the same order as *values*.

    Raises:
        ValueError: If any entry is not valid hex or not exactly 32 bytes.
    """
    fork_hashes: list[bytes] = []
    for value in values:
        try:
            raw = bytes.fromhex(value.strip())
        except ValueError as exc:
            raise ValueError(f"invalid fork hash hex: {value!r}") from exc

        if len(raw) != 32:
            raise ValueError(
                f"fork hash must be 32 bytes (64 hex chars), got {len(raw)}"
            )
        fork_hashes.append(raw)

    return fork_hashes


def extension_bits(version: int) -> int:
    """Compute the extension capability bitmask for a given extension version.

    Matches the encoding used in the Beam Login handshake flags field.

    Args:
        version: Numeric extension protocol version (e.g. ``11``).

    Returns:
        Integer bitmask representing all capabilities up to *version*.
    """
    if version < 4:
        return (1 << version) - 1
    return ((version - 4 + 1) << 4) - 1


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string ending in ``Z``.

    Returns:
        UTC timestamp string, e.g. ``"2026-04-05T12:34:56.789012Z"``.
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")