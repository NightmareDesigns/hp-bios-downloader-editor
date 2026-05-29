"""Tests for hp_bios_tool.cli (command-line interface)."""

import sys
import pytest
from pathlib import Path
from unittest.mock import patch

from hp_bios_tool.cli import build_parser, main
from hp_bios_tool.downloader import SoftPaqEntry
from hp_bios_tool.system_info import LocalSystemInfo


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParser:
    def test_subcommands_present(self):
        parser = build_parser()
        # Should not raise
        args = parser.parse_args(["hexdump", "--offset", "0", "--length", "16", "f.bin"])
        assert args.command == "hexdump"

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["hexdump", "f.bin"])
        assert args.verbose is False
        args2 = parser.parse_args(["-v", "hexdump", "f.bin"])
        assert args2.verbose is True

    def test_no_subcommand_exits(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])


# ---------------------------------------------------------------------------
# cmd_hexdump
# ---------------------------------------------------------------------------

class TestCmdHexdump:
    def test_basic(self, tmp_path, capsys):
        f = tmp_path / "test.bin"
        f.write_bytes(bytes(range(32)))
        rc = main(["hexdump", str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "00000000" in out

    def test_with_offset_and_length(self, tmp_path, capsys):
        f = tmp_path / "test.bin"
        f.write_bytes(bytes(range(256)))
        rc = main(["hexdump", "--offset", "0x10", "--length", "16", str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "00000010" in out


# ---------------------------------------------------------------------------
# cmd_edit
# ---------------------------------------------------------------------------

SAMPLE_REPSET = """\
BIOSConfig 1.0
;

USB Legacy Support
\t*Enabled
\tDisabled

Network Boot
\t*Enabled
\tDisabled

"""


class TestCmdEdit:
    def test_list(self, tmp_path, capsys):
        f = tmp_path / "bios.REPSET"
        f.write_text(SAMPLE_REPSET)
        rc = main(["edit", str(f), "--list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "USB Legacy Support" in out

    def test_find(self, tmp_path, capsys):
        f = tmp_path / "bios.REPSET"
        f.write_text(SAMPLE_REPSET)
        rc = main(["edit", str(f), "--find", "USB"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "USB Legacy Support" in out

    def test_set_saves_file(self, tmp_path):
        src = tmp_path / "bios.REPSET"
        src.write_text(SAMPLE_REPSET)
        out = tmp_path / "modified.REPSET"
        rc = main(["edit", str(src), "--set", "USB Legacy Support=Disabled", "--output", str(out)])
        assert rc == 0
        assert out.exists()
        content = out.read_text()
        assert "*Disabled" in content

    def test_set_invalid_value_returns_1(self, tmp_path):
        f = tmp_path / "bios.REPSET"
        f.write_text(SAMPLE_REPSET)
        rc = main(["edit", str(f), "--set", "USB Legacy Support=BadValue"])
        assert rc == 1

    def test_set_bad_format_returns_1(self, tmp_path):
        f = tmp_path / "bios.REPSET"
        f.write_text(SAMPLE_REPSET)
        rc = main(["edit", str(f), "--set", "NoEqualsSign"])
        assert rc == 1


# ---------------------------------------------------------------------------
# cmd_info
# ---------------------------------------------------------------------------

class TestCmdInfo:
    def test_basic(self, tmp_path, capsys):
        f = tmp_path / "bios.bin"
        f.write_bytes(b"\x00" * 256)
        rc = main(["info", str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Size" in out
        assert "MD5" in out
        assert "SHA256" in out

    def test_find_hidden_flag(self, tmp_path, capsys):
        f = tmp_path / "bios.bin"
        f.write_bytes(b"\x00" * 512)
        rc = main(["info", str(f), "--find-hidden"])
        assert rc == 0


# ---------------------------------------------------------------------------
# cmd_unlock
# ---------------------------------------------------------------------------

def make_synthetic_bios() -> bytes:
    """Return a minimal synthetic BIOS with one SUPPRESS_IF TRUE."""
    from hp_bios_tool.secret_menu import IFROpCode

    def make_opcode(op, payload=b"", scope=False):
        length = 2 + len(payload)
        lb = length | (0x80 if scope else 0)
        return bytes([op, lb]) + payload

    formset_payload = b"\x00" * 18  # GUID + extra
    formset = make_opcode(IFROpCode.FORM_SET, formset_payload, scope=True)
    suppress = make_opcode(IFROpCode.SUPPRESS_IF, scope=True)
    true_op = make_opcode(IFROpCode.TRUE)
    end = make_opcode(IFROpCode.END)
    return formset + suppress + true_op + end + b"\x00" * 64


class TestCmdUnlock:
    def test_report(self, tmp_path, capsys):
        f = tmp_path / "bios.bin"
        f.write_bytes(make_synthetic_bios())
        rc = main(["unlock", str(f), "--report"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "BIOS" in out or "Hidden" in out

    def test_dry_run(self, tmp_path, capsys):
        f = tmp_path / "bios.bin"
        data = make_synthetic_bios()
        f.write_bytes(data)
        rc = main(["unlock", str(f), "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Dry run" in out
        # Original file must be unchanged
        assert f.read_bytes() == data

    def test_unlock_patches_and_saves(self, tmp_path, capsys):
        f = tmp_path / "bios.bin"
        data = make_synthetic_bios()
        f.write_bytes(data)
        out_path = tmp_path / "bios_unlocked.bin"
        rc = main(["unlock", str(f), "--output", str(out_path)])
        assert rc == 0
        assert out_path.exists()
        # Patched file should differ from original
        assert out_path.read_bytes() != data

    def test_unlock_no_hidden_items(self, tmp_path, capsys):
        f = tmp_path / "bios.bin"
        f.write_bytes(b"\x00" * 512)
        rc = main(["unlock", str(f)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "No SUPPRESS_IF TRUE" in out or "No" in out


# ---------------------------------------------------------------------------
# cmd_download (mocked, no network)
# ---------------------------------------------------------------------------

class TestCmdDownload:
    def test_download_requires_args(self, capsys):
        rc = main(["download"])
        assert rc == 1

    def test_download_by_url_mocked(self, tmp_path, capsys):
        dummy = tmp_path / "sp99999.exe"
        dummy.write_bytes(b"EXE_DATA")

        with patch("hp_bios_tool.downloader.urlretrieve",
                   side_effect=lambda url, dest, **kw: Path(dest).write_bytes(b"EXE_DATA")):
            rc = main(["download", "--url",
                       "https://ftp.hp.com/pub/softpaq/sp99999.exe",
                       "--output-dir", str(tmp_path)])
        assert rc == 0

    def test_download_this_pc_uses_detected_product_id(self, capsys):
        entry = SoftPaqEntry(
            softpaq_id="sp12345",
            name="HP BIOS",
            version="1.2.3",
            description="desc",
            category="BIOS",
            url="https://ftp.hp.com/pub/softpaq/sp12345.exe",
            size_bytes=1024,
        )
        info = LocalSystemInfo(
            vendor="HP",
            product_name="HP EliteBook 840 G7",
            product_id="G3Z82UA",
            bios_version="01.02.03",
            bios_vendor="HP",
        )
        with patch("hp_bios_tool.system_info.detect_local_system", return_value=info), \
             patch("hp_bios_tool.downloader.BIOSDownloader.search_by_product_id", return_value=[entry]) as search_pid, \
             patch("hp_bios_tool.downloader.BIOSDownloader.search") as search_model:
            rc = main(["download", "--this-pc"])
        assert rc == 0
        search_pid.assert_called_once_with("G3Z82UA")
        search_model.assert_not_called()
        out = capsys.readouterr().out
        assert "Detected system" in out

    def test_download_this_pc_falls_back_to_model_search(self, capsys):
        entry = SoftPaqEntry(
            softpaq_id="sp12345",
            name="HP BIOS",
            version="1.2.3",
            description="desc",
            category="BIOS",
            url="https://ftp.hp.com/pub/softpaq/sp12345.exe",
            size_bytes=1024,
        )
        info = LocalSystemInfo(
            vendor="HP",
            product_name="HP EliteBook 840 G7",
            product_id="G3Z82UA",
            bios_version="01.02.03",
            bios_vendor="HP",
        )
        with patch("hp_bios_tool.system_info.detect_local_system", return_value=info), \
             patch("hp_bios_tool.downloader.BIOSDownloader.search_by_product_id", return_value=[]), \
             patch("hp_bios_tool.downloader.BIOSDownloader.search", return_value=[entry]) as search_model:
            rc = main(["download", "--this-pc"])
        assert rc == 0
        search_model.assert_called_once_with("HP EliteBook 840 G7", limit=10)
        out = capsys.readouterr().out
        assert "falling back to model search" in out

    def test_download_this_pc_rejects_conflicting_args(self, capsys):
        rc = main(["download", "--this-pc", "--query", "EliteBook"])
        assert rc == 1
