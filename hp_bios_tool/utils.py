"""Shared utility helpers for the HP BIOS tool."""

from __future__ import annotations

import hashlib
import struct
import uuid
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Hex / binary helpers
# ---------------------------------------------------------------------------

def hex_dump(data: bytes, start_offset: int = 0, width: int = 16) -> str:
    """Return a classic hex-dump string of *data*.

    Args:
        data: Raw bytes to dump.
        start_offset: Offset printed on the left-hand side.
        width: Number of bytes per row.

    Returns:
        Multi-line hex-dump string.
    """
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{start_offset + i:08x}  {hex_part:<{width * 3}}  |{asc_part}|")
    return "\n".join(lines)


def find_all(haystack: bytes, needle: bytes) -> Iterator[int]:
    """Yield every offset where *needle* appears inside *haystack*."""
    start = 0
    while True:
        pos = haystack.find(needle, start)
        if pos == -1:
            break
        yield pos
        start = pos + 1


# ---------------------------------------------------------------------------
# Checksum helpers
# ---------------------------------------------------------------------------

def checksum8(data: bytes) -> int:
    """Return the 8-bit two's-complement checksum of *data*."""
    return (-(sum(data)) & 0xFF)


def md5_file(path: Path) -> str:
    """Return the MD5 hex-digest of the file at *path*."""
    h = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex-digest of the file at *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# UEFI GUID helpers
# ---------------------------------------------------------------------------

def guid_bytes_to_str(raw: bytes) -> str:
    """Convert a 16-byte little-endian UEFI GUID to its canonical string.

    UEFI stores GUIDs in a mixed-endian layout:
      - DWORD (LE)
      - WORD  (LE)
      - WORD  (LE)
      - 8 bytes (big-endian array)

    Args:
        raw: Exactly 16 bytes.

    Returns:
        Canonical GUID string, e.g. ``"ef9fc172-a1b2-4693-b327-6d32fc416042"``.

    Raises:
        ValueError: If *raw* is not exactly 16 bytes.
    """
    if len(raw) != 16:
        raise ValueError(f"Expected 16 bytes for a GUID, got {len(raw)}")
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:]
    return (
        f"{d1:08x}-{d2:04x}-{d3:04x}-"
        f"{d4[0]:02x}{d4[1]:02x}-"
        + "".join(f"{b:02x}" for b in d4[2:])
    )


def str_to_guid_bytes(guid_str: str) -> bytes:
    """Convert a canonical GUID string to a 16-byte little-endian UEFI GUID.

    Args:
        guid_str: GUID string such as ``"ef9fc172-a1b2-4693-b327-6d32fc416042"``.

    Returns:
        16 raw bytes in UEFI (mixed-endian) layout.
    """
    u = uuid.UUID(guid_str)
    # uuid stores fields in big-endian; convert to UEFI mixed-endian
    fields = u.fields  # (time_low, time_mid, time_hi_version, clock_seq_hi_variant, clock_seq_low, node)
    d1 = struct.pack("<I", fields[0])
    d2 = struct.pack("<H", fields[1])
    d3 = struct.pack("<H", fields[2])
    # clock_seq (two 8-bit fields) + node (48-bit)
    d4_hi = struct.pack(">H", (fields[3] << 8) | fields[4])
    d4_lo = fields[5].to_bytes(6, "big")
    return d1 + d2 + d3 + d4_hi + d4_lo


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def ensure_dir(path: Path) -> Path:
    """Create *path* (and parents) if it does not exist; return *path*."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically (write to .tmp, then rename).

    Args:
        path: Destination file path.
        data: Raw bytes to write.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
