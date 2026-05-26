"""Tests for hp_bios_tool.editor (REPSET + binary editor)."""

import pytest
from pathlib import Path

from hp_bios_tool.editor import (
    BIOSConfigEditor,
    BIOSSetting,
    BIOSBinaryEditor,
    BinaryPatch,
)


# ---------------------------------------------------------------------------
# Sample REPSET text
# ---------------------------------------------------------------------------

SAMPLE_REPSET = """\
BIOSConfig 1.0
;     HP BIOS Configuration
;

USB Legacy Support
\t*Enabled
\tDisabled

Virtualization Technology (VTx)
\t*Enabled
\tDisabled

Secure Boot
\tEnabled
\t*Disabled

Serial Number
; Read Only
\t*SN12345678

Network Boot
\t*Enabled
\tDisabled

"""


# ---------------------------------------------------------------------------
# BIOSConfigEditor tests
# ---------------------------------------------------------------------------

class TestBIOSConfigEditorParse:
    def setup_method(self):
        self.editor = BIOSConfigEditor.from_text(SAMPLE_REPSET)

    def test_version_parsed(self):
        assert self.editor.version == "1.0"

    def test_setting_count(self):
        settings = self.editor.list_settings()
        assert len(settings) == 5

    def test_selected_value(self):
        s = self.editor.get("USB Legacy Support")
        assert s is not None
        assert s.selected == "Enabled"

    def test_options_parsed(self):
        s = self.editor.get("USB Legacy Support")
        assert "Enabled" in s.options
        assert "Disabled" in s.options

    def test_non_default_selected(self):
        s = self.editor.get("Secure Boot")
        assert s.selected == "Disabled"

    def test_read_only_flag(self):
        s = self.editor.get("Serial Number")
        assert s.read_only is True

    def test_nonexistent_returns_none(self):
        assert self.editor.get("Does Not Exist") is None

    def test_header_comment_preserved(self):
        assert any("HP BIOS Configuration" in c for c in self.editor.header_comment)


class TestBIOSConfigEditorSet:
    def setup_method(self):
        self.editor = BIOSConfigEditor.from_text(SAMPLE_REPSET)

    def test_set_valid_value(self):
        self.editor.set("USB Legacy Support", "Disabled")
        assert self.editor.get("USB Legacy Support").selected == "Disabled"

    def test_set_invalid_value_raises(self):
        with pytest.raises(ValueError, match="Invalid value"):
            self.editor.set("USB Legacy Support", "NotAValue")

    def test_set_unknown_name_raises(self):
        with pytest.raises(KeyError):
            self.editor.set("FakeOption", "Something")

    def test_set_many(self):
        self.editor.set_many({
            "USB Legacy Support": "Disabled",
            "Network Boot": "Disabled",
        })
        assert self.editor.get("USB Legacy Support").selected == "Disabled"
        assert self.editor.get("Network Boot").selected == "Disabled"


class TestBIOSConfigEditorFind:
    def setup_method(self):
        self.editor = BIOSConfigEditor.from_text(SAMPLE_REPSET)

    def test_find_case_insensitive(self):
        results = self.editor.find("usb")
        assert len(results) == 1
        assert results[0].name == "USB Legacy Support"

    def test_find_partial_match(self):
        results = self.editor.find("Boot")
        names = [r.name for r in results]
        assert "Secure Boot" in names
        assert "Network Boot" in names

    def test_find_no_match(self):
        results = self.editor.find("xyzzy")
        assert results == []


class TestBIOSConfigEditorSerialise:
    def setup_method(self):
        self.editor = BIOSConfigEditor.from_text(SAMPLE_REPSET)

    def test_round_trip(self):
        """Parse → serialise → re-parse and check values are identical."""
        text = self.editor.to_text()
        editor2 = BIOSConfigEditor.from_text(text)
        for s in self.editor.list_settings():
            s2 = editor2.get(s.name)
            assert s2 is not None, f"Setting {s.name!r} missing after round-trip"
            assert s2.selected == s.selected

    def test_header_in_output(self):
        text = self.editor.to_text()
        assert "BIOSConfig" in text

    def test_selected_marked_with_asterisk(self):
        text = self.editor.to_text()
        # "USB Legacy Support" selected = "Enabled"
        assert "\t*Enabled" in text

    def test_save_file(self, tmp_path):
        out = tmp_path / "out.REPSET"
        self.editor.save(out)
        assert out.exists()
        content = out.read_text()
        assert "BIOSConfig" in content


class TestBIOSConfigEditorDiff:
    def test_diff_detects_change(self):
        a = BIOSConfigEditor.from_text(SAMPLE_REPSET)
        b = BIOSConfigEditor.from_text(SAMPLE_REPSET)
        b.set("USB Legacy Support", "Disabled")
        diff = a.diff(b)
        assert any("USB Legacy Support" in line for line in diff)

    def test_diff_no_change(self):
        a = BIOSConfigEditor.from_text(SAMPLE_REPSET)
        b = BIOSConfigEditor.from_text(SAMPLE_REPSET)
        diff = a.diff(b)
        assert diff == []


class TestAddSetting:
    def test_add_new_setting(self):
        editor = BIOSConfigEditor.from_text(SAMPLE_REPSET)
        new_s = BIOSSetting(
            name="Custom Hidden Option",
            selected="Enabled",
            options=["Enabled", "Disabled"],
        )
        editor.add_setting(new_s)
        assert editor.get("Custom Hidden Option") is not None

    def test_replace_existing_setting(self):
        editor = BIOSConfigEditor.from_text(SAMPLE_REPSET)
        new_s = BIOSSetting(
            name="USB Legacy Support",
            selected="Disabled",
            options=["Enabled", "Disabled"],
        )
        editor.add_setting(new_s)
        assert editor.get("USB Legacy Support").selected == "Disabled"


# ---------------------------------------------------------------------------
# BIOSBinaryEditor tests
# ---------------------------------------------------------------------------

class TestBIOSBinaryEditor:
    SAMPLE = bytes(range(256))

    def test_from_bytes(self):
        ed = BIOSBinaryEditor(self.SAMPLE)
        assert ed.size == 256

    def test_from_file(self, tmp_path):
        f = tmp_path / "bios.bin"
        f.write_bytes(self.SAMPLE)
        ed = BIOSBinaryEditor.from_file(f)
        assert ed.size == 256

    def test_hexdump(self):
        ed = BIOSBinaryEditor(self.SAMPLE)
        dump = ed.hexdump(0, 16)
        assert "00000000" in dump

    def test_search_found(self):
        ed = BIOSBinaryEditor(b"AAABBBCCCAAA")
        offsets = ed.search(b"AAA")
        assert 0 in offsets
        assert 9 in offsets

    def test_search_not_found(self):
        ed = BIOSBinaryEditor(b"AAABBB")
        assert ed.search(b"ZZZ") == []

    def test_apply_patch_success(self):
        data = bytearray(b"Hello World")
        ed = BIOSBinaryEditor(bytes(data))
        patch = BinaryPatch(
            offset=6,
            original=b"World",
            replacement=b"BIOS!",
            description="test patch",
        )
        ed.apply_patch(patch)
        assert ed.to_bytes()[6:11] == b"BIOS!"

    def test_apply_patch_strict_mismatch(self):
        ed = BIOSBinaryEditor(b"Hello World")
        patch = BinaryPatch(
            offset=0,
            original=b"Hxxxx",
            replacement=b"Hyyyy",
            description="bad patch",
        )
        with pytest.raises(ValueError, match="expected"):
            ed.apply_patch(patch, strict=True)

    def test_apply_patch_non_strict(self):
        ed = BIOSBinaryEditor(b"Hello World")
        patch = BinaryPatch(
            offset=0,
            original=b"Hxxxx",
            replacement=b"Hzzzz",
            description="forced patch",
        )
        ed.apply_patch(patch, strict=False)  # should not raise
        assert ed.to_bytes()[:5] == b"Hzzzz"

    def test_apply_patch_size_mismatch(self):
        ed = BIOSBinaryEditor(b"Hello World")
        patch = BinaryPatch(
            offset=0,
            original=b"Hello",
            replacement=b"Hi",
            description="bad size",
        )
        with pytest.raises(ValueError, match="length"):
            ed.apply_patch(patch)

    def test_apply_patch_out_of_range(self):
        ed = BIOSBinaryEditor(b"Hi")
        patch = BinaryPatch(
            offset=10,
            original=b"Hi",
            replacement=b"By",
            description="out of range",
        )
        with pytest.raises(IndexError):
            ed.apply_patch(patch)

    def test_write_bytes(self):
        ed = BIOSBinaryEditor(b"AAAAAA")
        ed.write_bytes(2, b"BB")
        assert ed.to_bytes() == b"AABBAA"

    def test_write_bytes_out_of_range(self):
        ed = BIOSBinaryEditor(b"AB")
        with pytest.raises(IndexError):
            ed.write_bytes(10, b"X")

    def test_save(self, tmp_path):
        ed = BIOSBinaryEditor(b"test data")
        out = tmp_path / "out.bin"
        ed.save(out)
        assert out.read_bytes() == b"test data"

    def test_apply_patches(self):
        ed = BIOSBinaryEditor(b"AABBCC")
        patches = [
            BinaryPatch(0, b"AA", b"XX", "first"),
            BinaryPatch(4, b"CC", b"YY", "second"),
        ]
        ed.apply_patches(patches)
        assert ed.to_bytes() == b"XXBBYY"
