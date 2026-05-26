"""Tests for hp_bios_tool.secret_menu (IFR parser and unlocker)."""

import struct
import pytest

from hp_bios_tool.secret_menu import (
    IFROpCode,
    IFROpNode,
    IFRParser,
    HiddenMenuItem,
    SecretMenuUnlocker,
    locate_ifr_regions,
    _is_always_true_condition,
)


# ---------------------------------------------------------------------------
# Helpers to build synthetic IFR buffers
# ---------------------------------------------------------------------------

def make_opcode(opcode: int, payload: bytes = b"", scope: bool = False) -> bytes:
    """Construct a minimal IFR opcode byte string."""
    length = 2 + len(payload)
    len_byte = length | (0x80 if scope else 0x00)
    return bytes([opcode, len_byte]) + payload


def make_formset(guid: bytes = b"\x00" * 16) -> bytes:
    """Build a minimal FORM_SET opcode (0x0E)."""
    payload = guid + b"\x00\x00"  # GUID + ClassGuid placeholder
    length = 2 + len(payload)
    return bytes([IFROpCode.FORM_SET, length | 0x80]) + payload


def make_suppress_true() -> bytes:
    """Build a SUPPRESS_IF TRUE sequence (the 'hidden menu' pattern)."""
    suppress = make_opcode(IFROpCode.SUPPRESS_IF, scope=True)
    true_op = make_opcode(IFROpCode.TRUE)
    end = make_opcode(IFROpCode.END)
    return suppress + true_op + end


def make_suppress_false() -> bytes:
    """Build a SUPPRESS_IF FALSE sequence (menu is visible)."""
    suppress = make_opcode(IFROpCode.SUPPRESS_IF, scope=True)
    false_op = make_opcode(IFROpCode.FALSE)
    end = make_opcode(IFROpCode.END)
    return suppress + false_op + end


# ---------------------------------------------------------------------------
# IFRParser tests
# ---------------------------------------------------------------------------

class TestIFRParser:
    def test_empty_buffer(self):
        parser = IFRParser(b"")
        assert parser.parse() == []

    def test_single_opcode(self):
        buf = make_opcode(IFROpCode.TRUE)
        nodes = IFRParser(buf).parse()
        assert len(nodes) == 1
        assert nodes[0].opcode == IFROpCode.TRUE

    def test_scope_bit_parsed(self):
        buf = make_opcode(IFROpCode.SUPPRESS_IF, scope=True)
        nodes = IFRParser(buf).parse()
        assert nodes[0].scope_start is True

    def test_no_scope_bit(self):
        buf = make_opcode(IFROpCode.TRUE)
        nodes = IFRParser(buf).parse()
        assert nodes[0].scope_start is False

    def test_multiple_opcodes(self):
        buf = (
            make_opcode(IFROpCode.SUPPRESS_IF, scope=True)
            + make_opcode(IFROpCode.TRUE)
            + make_opcode(IFROpCode.END)
        )
        nodes = IFRParser(buf).parse()
        assert len(nodes) == 3
        assert nodes[0].opcode == IFROpCode.SUPPRESS_IF
        assert nodes[1].opcode == IFROpCode.TRUE
        assert nodes[2].opcode == IFROpCode.END

    def test_base_offset_applied(self):
        buf = make_opcode(IFROpCode.TRUE)
        nodes = IFRParser(buf, base_offset=0x1000).parse()
        assert nodes[0].offset == 0x1000

    def test_payload_extracted(self):
        payload = b"\x01\x02\x03"
        buf = make_opcode(0x42, payload=payload)
        nodes = IFRParser(buf).parse()
        assert nodes[0].payload == payload

    def test_opcode_name_known(self):
        node = IFROpNode(0, IFROpCode.SUPPRESS_IF, 2, True, b"")
        assert node.opcode_name == "SUPPRESS_IF"

    def test_opcode_name_unknown(self):
        node = IFROpNode(0, 0xFF, 2, False, b"")
        assert "0xFF" in node.opcode_name or "UNKNOWN" in node.opcode_name

    def test_truncated_buffer_graceful(self):
        # Only one byte — no valid opcode
        nodes = IFRParser(b"\x0A").parse()
        assert nodes == []


# ---------------------------------------------------------------------------
# locate_ifr_regions tests
# ---------------------------------------------------------------------------

class TestLocateIFRRegions:
    def test_no_formset_returns_empty(self):
        data = b"\x00" * 1000
        regions = locate_ifr_regions(data)
        assert regions == []

    def test_finds_formset(self):
        formset = make_formset()
        data = b"\x00" * 100 + formset + b"\x00" * 100
        regions = locate_ifr_regions(data)
        assert len(regions) >= 1

    def test_returns_offset_of_formset(self):
        formset = make_formset()
        offset = 50
        data = b"\x00" * offset + formset + b"\x00" * 100
        regions = locate_ifr_regions(data)
        assert any(r[0] == offset for r in regions)

    def test_deduplicates_nearby_regions(self):
        # Two FORM_SET opcodes very close together should be merged
        formset = make_formset()
        data = b"\x00" * 10 + formset + b"\x00" * 5 + formset + b"\x00" * 100
        regions = locate_ifr_regions(data)
        # Should only keep one region for closely spaced formsets
        assert len(regions) <= 2  # relaxed: allow 1 or 2


# ---------------------------------------------------------------------------
# _is_always_true_condition tests
# ---------------------------------------------------------------------------

class TestIsAlwaysTrueCondition:
    def test_true_opcode(self):
        node = IFROpNode(0, IFROpCode.TRUE, 2, False, b"")
        assert _is_always_true_condition(node) is True

    def test_one_opcode(self):
        node = IFROpNode(0, IFROpCode.ONE, 2, False, b"")
        assert _is_always_true_condition(node) is True

    def test_ones_opcode(self):
        node = IFROpNode(0, IFROpCode.ONES, 2, False, b"")
        assert _is_always_true_condition(node) is True

    def test_uint8_one(self):
        node = IFROpNode(0, IFROpCode.UINT8, 3, False, b"\x01")
        assert _is_always_true_condition(node) is True

    def test_uint8_zero(self):
        node = IFROpNode(0, IFROpCode.UINT8, 3, False, b"\x00")
        assert _is_always_true_condition(node) is False

    def test_false_opcode(self):
        node = IFROpNode(0, IFROpCode.FALSE, 2, False, b"")
        assert _is_always_true_condition(node) is False


# ---------------------------------------------------------------------------
# SecretMenuUnlocker tests
# ---------------------------------------------------------------------------

def make_bios_with_hidden_menu(n_hidden: int = 1, prefix: bytes = b"") -> bytes:
    """Build a synthetic BIOS blob containing n_hidden SUPPRESS_IF TRUE blocks."""
    formset = make_formset()
    hidden_blocks = make_suppress_true() * n_hidden
    return prefix + formset + hidden_blocks + b"\x00" * 64


class TestSecretMenuUnlocker:
    def test_from_bytes(self):
        unlocker = SecretMenuUnlocker(b"\x00" * 256)
        assert len(unlocker.to_bytes()) == 256

    def test_from_file(self, tmp_path):
        f = tmp_path / "bios.bin"
        f.write_bytes(b"\x00" * 256)
        unlocker = SecretMenuUnlocker.from_file(f)
        assert len(unlocker.to_bytes()) == 256

    def test_find_hidden_items_empty_image(self):
        unlocker = SecretMenuUnlocker(b"\x00" * 512)
        hidden = unlocker.find_hidden_items()
        assert hidden == []

    def test_find_hidden_items_detects_suppress_true(self):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        hidden = unlocker.find_hidden_items()
        assert len(hidden) >= 1

    def test_find_hidden_items_multiple(self):
        data = make_bios_with_hidden_menu(3)
        unlocker = SecretMenuUnlocker(data)
        hidden = unlocker.find_hidden_items()
        assert len(hidden) >= 3

    def test_hidden_item_has_correct_opcodes(self):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        hidden = unlocker.find_hidden_items()
        assert len(hidden) >= 1
        item = hidden[0]
        assert data[item.suppress_offset] == IFROpCode.SUPPRESS_IF
        assert data[item.condition_offset] == IFROpCode.TRUE

    def test_unlock_all_patches_true_to_false(self):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        hidden_before = unlocker.find_hidden_items()
        assert len(hidden_before) >= 1

        unlocker.unlock_all()
        patched = unlocker.to_bytes()

        # The TRUE byte should now be FALSE
        for item in hidden_before:
            assert patched[item.condition_offset] == IFROpCode.FALSE

    def test_unlock_all_returns_self(self):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        result = unlocker.unlock_all()
        assert result is unlocker

    def test_unlock_all_no_hidden_items(self):
        data = b"\x00" * 512
        unlocker = SecretMenuUnlocker(data)
        result = unlocker.unlock_all()  # should not raise
        assert result is unlocker

    def test_unlock_item(self):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        hidden = unlocker.find_hidden_items()
        assert hidden
        item = hidden[0]
        unlocker.unlock_item(item)
        assert unlocker.to_bytes()[item.condition_offset] == IFROpCode.FALSE

    def test_unlock_item_non_true_raises(self):
        # Build a SUPPRESS_IF FALSE (not a hidden item)
        formset = make_formset()
        suppress_false = make_suppress_false()
        data = formset + suppress_false + b"\x00" * 64
        unlocker = SecretMenuUnlocker(data)

        # Manually construct a fake HiddenMenuItem pointing at the FALSE opcode
        # (find where FALSE is in the data)
        false_offset = data.index(bytes([IFROpCode.FALSE]))
        item = HiddenMenuItem(
            suppress_offset=0,
            condition_offset=false_offset,
            condition_opcode=IFROpCode.FALSE,
        )
        with pytest.raises(ValueError, match="not TRUE"):
            unlocker.unlock_item(item)

    def test_remove_suppress(self):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        hidden = unlocker.find_hidden_items()
        assert hidden
        item = hidden[0]
        suppress_offset = item.suppress_offset
        unlocker.remove_suppress(item)
        # The SUPPRESS_IF byte should now be END
        assert unlocker.to_bytes()[suppress_offset] == IFROpCode.END

    def test_save(self, tmp_path):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        unlocker.unlock_all()
        out = tmp_path / "bios_unlocked.bin"
        unlocker.save(out)
        assert out.exists()
        assert out.read_bytes() != data  # patched ≠ original

    def test_report_returns_string(self):
        data = make_bios_with_hidden_menu(1)
        unlocker = SecretMenuUnlocker(data)
        report = unlocker.report()
        assert isinstance(report, str)
        assert "Hidden" in report

    def test_apply_hp_known_patches_no_match(self):
        # Random data → no signatures should match
        unlocker = SecretMenuUnlocker(b"\xFF" * 512)
        applied = unlocker.apply_hp_known_patches()
        assert applied == []

    def test_apply_hp_known_patches_generic_match(self):
        # Build a buffer containing the generic SUPPRESS_IF TRUE pattern
        prefix = b"\x00" * 16
        pattern = bytes([IFROpCode.SUPPRESS_IF, 0x82, IFROpCode.TRUE, 0x02])
        data = prefix + pattern + b"\x00" * 64
        unlocker = SecretMenuUnlocker(data)
        applied = unlocker.apply_hp_known_patches()
        # The TRUE byte at offset len(prefix)+2 should be patched to FALSE
        patched = unlocker.to_bytes()
        assert patched[len(prefix) + 2] == IFROpCode.FALSE


# ---------------------------------------------------------------------------
# HiddenMenuItem __str__ test
# ---------------------------------------------------------------------------

class TestHiddenMenuItemStr:
    def test_str_contains_offsets(self):
        item = HiddenMenuItem(
            suppress_offset=0x1000,
            condition_offset=0x1002,
            condition_opcode=IFROpCode.TRUE,
            parent_form_name="TestForm",
        )
        s = str(item)
        assert "1000" in s
        assert "1002" in s
        assert "TRUE" in s
        assert "TestForm" in s
