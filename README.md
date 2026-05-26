# hp-bios-downloader-editor

**NightmareDesigns** — HP BIOS Downloader, Editor, and Secret-Menu Unlocker

A Python-based toolkit for working with HP UEFI BIOS firmware:

| Feature | Description |
|---------|-------------|
| 📥 **Downloader** | Search and download HP BIOS SoftPaq packages from HP's public catalog |
| ✏️ **Editor** | Parse and modify HP BIOS configuration (REPSET) files and binary images |
| 🔓 **Secret-Menu Unlocker** | Find and patch UEFI IFR suppression conditions to expose hidden BIOS menus |

---

## Requirements

- Python 3.8 or newer
- `requests` (auto-installed)
- Optional: `7z` / `p7zip` or `cabextract` (for SoftPaq extraction)

---

## Installation

```bash
git clone https://github.com/NightmareDesigns/hp-bios-downloader-editor.git
cd hp-bios-downloader-editor
pip install -e .
```

This installs the `hp-bios` command-line tool.

---

## Usage

### `download` — Fetch HP BIOS SoftPaqs

Search HP's SoftPaq catalog and download BIOS packages.

```bash
# Search by model name
hp-bios download --query "HP EliteBook 840 G7"

# Search by HP product ID (the part before '#' in the full product number)
hp-bios download --product-id G3Z82UA

# Download the top search result automatically
hp-bios download --query "EliteBook 840 G7" --download-first --output-dir ./downloads

# Download and extract the SoftPaq
hp-bios download --query "EliteBook 840 G7" --download-first --extract

# Download a specific SoftPaq by direct URL
hp-bios download --url https://ftp.hp.com/pub/softpaq/sp12345-12999/sp12345.exe
```

### `edit` — Edit HP BIOS REPSET Configuration Files

HP's **BIOS Configuration Utility (BCU)** exports settings as `.REPSET` text files.
This tool lets you view and change those settings without BCU.

```bash
# List all settings and their current values
hp-bios edit current.REPSET --list

# Show all allowed values for each setting
hp-bios edit current.REPSET --list --show-options

# Find settings matching a pattern
hp-bios edit current.REPSET --find "USB"
hp-bios edit current.REPSET --find "Boot"

# Change one or more settings and save
hp-bios edit current.REPSET \
    --set "USB Legacy Support=Disabled" \
    --set "Virtualization Technology (VTx)=Enabled" \
    --output modified.REPSET
```

**REPSET format example:**

```
BIOSConfig 1.0
;

USB Legacy Support
	*Enabled
	Disabled

Virtualization Technology (VTx)
	*Enabled
	Disabled
```

### `unlock` — Unlock Hidden BIOS Menus

HP UEFI BIOSes hide certain menus by embedding `SUPPRESS_IF TRUE` conditions in their
IFR (Internal Form Representation) data.  This command locates and patches those
conditions so the menus become visible.

```bash
# Analyse a BIOS image — show what would be patched (no changes written)
hp-bios unlock bios.bin --report

# Dry run — list hidden items without patching
hp-bios unlock bios.bin --dry-run

# Patch all SUPPRESS_IF TRUE conditions → expose hidden menus
hp-bios unlock bios.bin --output bios_unlocked.bin

# Also apply HP-specific known signature patches (Advanced tab, ME menu, etc.)
hp-bios unlock bios.bin --hp-patches --output bios_unlocked.bin
```

> ⚠️ **Always back up your original BIOS before flashing any modified image.**
> Flash at your own risk.  An incorrect BIOS flash can brick your device.

### `hexdump` — Inspect a BIOS Binary

```bash
# Dump the first 256 bytes
hp-bios hexdump bios.bin

# Dump 64 bytes starting at offset 0x1000
hp-bios hexdump bios.bin --offset 0x1000 --length 64
```

### `info` — Display BIOS File Information

```bash
# Show size, MD5, SHA-256, and IFR region locations
hp-bios info bios.bin

# Also scan for hidden menu items
hp-bios info bios.bin --find-hidden
```

---

## Python API

All functionality is accessible as a Python library:

```python
from hp_bios_tool.downloader import BIOSDownloader
from hp_bios_tool.editor import BIOSConfigEditor, BIOSBinaryEditor, BinaryPatch
from hp_bios_tool.secret_menu import SecretMenuUnlocker

# --- Download ---
dl = BIOSDownloader(output_dir="./bios_files")
results = dl.search("HP EliteBook 840 G7")
path = dl.download(results[0])

# --- Edit REPSET config ---
editor = BIOSConfigEditor.from_file("current.REPSET")
editor.set("USB Legacy Support", "Disabled")
editor.set("Virtualization Technology (VTx)", "Enabled")
editor.save("modified.REPSET")

# --- Binary patch ---
bed = BIOSBinaryEditor.from_file("bios.bin")
offsets = bed.search(b"\x0A\x82\x46\x02")
print(f"Pattern found at: {[hex(o) for o in offsets]}")
bed.apply_patch(BinaryPatch(
    offset=offsets[0] + 2,
    original=b"\x46",
    replacement=b"\x47",
    description="SUPPRESS_IF TRUE → FALSE",
))
bed.save("bios_patched.bin")

# --- Secret menu unlock ---
unlocker = SecretMenuUnlocker.from_file("bios.bin")
print(unlocker.report())          # analysis only
hidden = unlocker.find_hidden_items()
for item in hidden:
    print(item)
unlocker.unlock_all()             # patch all SUPPRESS_IF TRUE → FALSE
unlocker.save("bios_unlocked.bin")
```

---

## How the Secret-Menu Unlock Works

HP UEFI BIOSes define their setup menus using **IFR** (Internal Form Representation)
data stored inside the firmware.  Individual forms and questions can be hidden using:

- `EFI_IFR_SUPPRESS_IF` — hide the element if the condition is `TRUE`
- `EFI_IFR_GRAY_OUT_IF` — grey out the element if the condition is `TRUE`

A common pattern for permanently hidden menus is:

```
SUPPRESS_IF (scope open)
  TRUE          ← always TRUE → always hidden
  <menu content>
END
```

This tool:
1. Scans the BIOS binary for `FORM_SET` opcodes to locate IFR regions.
2. Parses each IFR opcode stream.
3. Finds `SUPPRESS_IF` + `TRUE` (or equivalent always-true opcode) patterns.
4. Patches the `TRUE` byte (`0x46`) to `FALSE` (`0x47`), making the menu visible.

---

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

---

## Disclaimer

This tool is provided for educational purposes and for use on hardware you own.
Modifying BIOS firmware carries risk.  The authors accept no responsibility for
damaged hardware resulting from improper use.  Always keep a backup of the
original BIOS image.
