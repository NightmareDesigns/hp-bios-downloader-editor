"""Tests for hp_bios_tool.system_info."""

import subprocess

import pytest

from hp_bios_tool.system_info import detect_linux_system, detect_windows_system


class TestDetectLinuxSystem:
    def test_reads_dmi_fields(self, tmp_path):
        (tmp_path / "sys_vendor").write_text("HP\n")
        (tmp_path / "product_name").write_text("EliteBook 840 G7\n")
        (tmp_path / "product_sku").write_text("G3Z82UA#ABA\n")
        (tmp_path / "bios_version").write_text("01.15.00\n")
        (tmp_path / "bios_vendor").write_text("HP\n")

        info = detect_linux_system(tmp_path)

        assert info.vendor == "HP"
        assert info.product_name == "EliteBook 840 G7"
        assert info.product_id == "G3Z82UA#ABA"
        assert info.bios_version == "01.15.00"


class TestDetectWindowsSystem:
    def test_uses_powershell_when_available(self):
        def runner(cmd, **kwargs):
            assert cmd[0] == "powershell"
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout=(
                    '{"vendor":"HP","product_name":"EliteBook 840 G7",'
                    '"product_id":"G3Z82UA","bios_version":"01.15.00","bios_vendor":"HP"}'
                ),
                stderr="",
            )

        info = detect_windows_system(runner=runner)

        assert info.vendor == "HP"
        assert info.product_name == "EliteBook 840 G7"
        assert info.product_id == "G3Z82UA"

    def test_falls_back_to_wmic(self):
        calls = []

        def runner(cmd, **kwargs):
            calls.append(cmd[0])
            if cmd[0] == "powershell":
                raise subprocess.CalledProcessError(1, cmd, output="", stderr="bad")
            if cmd[1] == "computersystem":
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=(
                        "Manufacturer=HP\n"
                        "Model=EliteBook 840 G7\n"
                        "SystemSKUNumber=G3Z82UA\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout="Manufacturer=HP\nSMBIOSBIOSVersion=01.15.00\n",
                stderr="",
            )

        info = detect_windows_system(runner=runner)

        assert calls == ["powershell", "wmic", "wmic"]
        assert info.vendor == "HP"
        assert info.product_name == "EliteBook 840 G7"
        assert info.product_id == "G3Z82UA"
