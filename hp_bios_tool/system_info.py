"""Helpers for detecting the current machine's HP system identifiers."""

from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class LocalSystemInfo:
    """Identifiers for the current machine."""

    vendor: str = ""
    product_name: str = ""
    product_id: str = ""
    bios_version: str = ""
    bios_vendor: str = ""

    @property
    def is_hp(self) -> bool:
        text = " ".join(
            part for part in (self.vendor, self.bios_vendor, self.product_name) if part
        ).lower()
        return "hewlett-packard" in text or "hp" in text

    def __str__(self) -> str:
        details: list[str] = []
        if self.vendor:
            details.append(self.vendor)
        if self.product_name:
            details.append(self.product_name)
        if self.product_id:
            details.append(f"SKU {self.product_id}")
        if self.bios_version:
            details.append(f"BIOS {self.bios_version}")
        return " / ".join(details) if details else "Unknown system"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except FileNotFoundError:
        return ""
    except PermissionError:
        return ""


def detect_linux_system(dmi_root: Path = Path("/sys/devices/virtual/dmi/id")) -> LocalSystemInfo:
    """Detect HP system identifiers from Linux DMI/sysfs."""
    return LocalSystemInfo(
        vendor=_read_text(dmi_root / "sys_vendor"),
        product_name=_read_text(dmi_root / "product_name"),
        product_id=_read_text(dmi_root / "product_sku"),
        bios_version=_read_text(dmi_root / "bios_version"),
        bios_vendor=_read_text(dmi_root / "bios_vendor"),
    )


def _parse_wmic_list(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def detect_windows_system(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> LocalSystemInfo:
    """Detect HP system identifiers from Windows CIM/WMI."""
    script = """
$sys = Get-CimInstance Win32_ComputerSystem
$product = Get-CimInstance Win32_ComputerSystemProduct
$bios = Get-CimInstance Win32_BIOS
@{
  vendor = $product.Vendor
  product_name = $sys.Model
  product_id = $sys.SystemSKUNumber
  bios_version = $bios.SMBIOSBIOSVersion
  bios_vendor = $bios.Manufacturer
} | ConvertTo-Json -Compress
"""
    try:
        result = runner(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout.strip() or "{}")
        return LocalSystemInfo(
            vendor=str(data.get("vendor", "")).strip(),
            product_name=str(data.get("product_name", "")).strip(),
            product_id=str(data.get("product_id", "")).strip(),
            bios_version=str(data.get("bios_version", "")).strip(),
            bios_vendor=str(data.get("bios_vendor", "")).strip(),
        )
    except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError):
        pass

    sys_result = runner(
        ["wmic", "computersystem", "get", "manufacturer,model,systemskunumber", "/format:list"],
        capture_output=True,
        text=True,
        check=True,
    )
    bios_result = runner(
        ["wmic", "bios", "get", "manufacturer,SMBIOSBIOSVersion", "/format:list"],
        capture_output=True,
        text=True,
        check=True,
    )
    sys_data = _parse_wmic_list(sys_result.stdout)
    bios_data = _parse_wmic_list(bios_result.stdout)
    return LocalSystemInfo(
        vendor=sys_data.get("Manufacturer", ""),
        product_name=sys_data.get("Model", ""),
        product_id=sys_data.get("SystemSKUNumber", ""),
        bios_version=bios_data.get("SMBIOSBIOSVersion", ""),
        bios_vendor=bios_data.get("Manufacturer", ""),
    )


def detect_local_system() -> LocalSystemInfo:
    """Detect identifiers for the current system."""
    system = platform.system()
    if system == "Linux":
        return detect_linux_system()
    if system == "Windows":
        return detect_windows_system()
    raise RuntimeError(f"Unsupported operating system for auto-detection: {system}")
