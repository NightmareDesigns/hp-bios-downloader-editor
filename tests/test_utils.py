"""Tests for hp_bios_tool.utils."""

import struct
import pytest

from hp_bios_tool.utils import (
    hex_dump,
    find_all,
    checksum8,
    guid_bytes_to_str,
    str_to_guid_bytes,
    safe_write,
    ensure_dir,
)


# ---------------------------------------------------------------------------
# hex_dump
# ---------------------------------------------------------------------------

class TestHexDump:
    def test_single_row(self):
        data = bytes(range(16))
        result = hex_dump(data)
        assert "00000000" in result
        assert "00 01 02 03" in result

    def test_start_offset(self):
        result = hex_dump(b"\x00" * 16, start_offset=0x100)
        assert "00000100" in result

    def test_printable_chars(self):
        result = hex_dump(b"Hello, World!!!")
        assert "Hello" in result

    def test_non_printable_replaced(self):
        result = hex_dump(bytes([0x00, 0x01]))
        assert ".." in result

    def test_empty_data(self):
        result = hex_dump(b"")
        assert result == ""

    def test_multi_row(self):
        data = bytes(range(32))
        result = hex_dump(data)
        lines = result.splitlines()
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# find_all
# ---------------------------------------------------------------------------

class TestFindAll:
    def test_single_occurrence(self):
        assert list(find_all(b"abcabc", b"abc")) == [0, 3]

    def test_no_occurrence(self):
        assert list(find_all(b"hello", b"xyz")) == []

    def test_overlapping(self):
        result = list(find_all(b"aaa", b"aa"))
        assert result == [0, 1]

    def test_needle_larger_than_haystack(self):
        assert list(find_all(b"ab", b"abc")) == []


# ---------------------------------------------------------------------------
# checksum8
# ---------------------------------------------------------------------------

class TestChecksum8:
    def test_known_value(self):
        # sum([0x01, 0x02, 0x03]) = 6; -6 & 0xFF = 250
        assert checksum8(bytes([0x01, 0x02, 0x03])) == 250

    def test_zero_data(self):
        assert checksum8(b"\x00\x00") == 0

    def test_single_byte(self):
        assert checksum8(bytes([0x10])) == ((-0x10) & 0xFF)

    def test_result_in_byte_range(self):
        for val in range(256):
            result = checksum8(bytes([val]))
            assert 0 <= result <= 255


# ---------------------------------------------------------------------------
# GUID helpers
# ---------------------------------------------------------------------------

class TestGUIDHelpers:
    # EFI_HII_DATABASE_PROTOCOL_GUID:
    # ef9fc172-a1b2-4693-b327-6d32fc416042
    GUID_STR = "ef9fc172-a1b2-4693-b327-6d32fc416042"

    def test_round_trip(self):
        raw = str_to_guid_bytes(self.GUID_STR)
        assert len(raw) == 16
        recovered = guid_bytes_to_str(raw)
        assert recovered == self.GUID_STR

    def test_guid_bytes_wrong_length(self):
        with pytest.raises(ValueError):
            guid_bytes_to_str(b"\x00" * 15)

    def test_str_to_bytes_known_guid(self):
        raw = str_to_guid_bytes(self.GUID_STR)
        # First 4 bytes: ef9fc172 in little-endian = 72 c1 9f ef
        assert raw[:4] == bytes([0x72, 0xC1, 0x9F, 0xEF])


# ---------------------------------------------------------------------------
# safe_write / ensure_dir
# ---------------------------------------------------------------------------

class TestSafeWrite:
    def test_writes_file(self, tmp_path):
        dest = tmp_path / "test.bin"
        safe_write(dest, b"hello")
        assert dest.read_bytes() == b"hello"

    def test_overwrites_file(self, tmp_path):
        dest = tmp_path / "test.bin"
        safe_write(dest, b"first")
        safe_write(dest, b"second")
        assert dest.read_bytes() == b"second"

    def test_no_tmp_leftover(self, tmp_path):
        dest = tmp_path / "test.bin"
        safe_write(dest, b"data")
        tmp = dest.with_suffix(".bin.tmp")
        assert not tmp.exists()


class TestEnsureDir:
    def test_creates_dir(self, tmp_path):
        new_dir = tmp_path / "a" / "b" / "c"
        result = ensure_dir(new_dir)
        assert result.is_dir()

    def test_existing_dir_ok(self, tmp_path):
        result = ensure_dir(tmp_path)
        assert result == tmp_path
