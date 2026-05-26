"""UEFI BIOS secret / hidden menu unlocker.

HP (and many other) UEFI BIOSes embed their setup-menu definitions as **IFR**
(Internal Form Representation) data inside the firmware.  Individual forms and
questions can be made invisible using ``EFI_IFR_SUPPRESS_IF`` or
``EFI_IFR_GRAY_OUT_IF`` opcodes that evaluate a condition.  A common pattern is
a condition that is hard-coded to ``TRUE``, permanently hiding the menu item.

This module:

1. Locates the UEFI HII (Human Interface Infrastructure) database inside a raw
   BIOS image.
2. Parses IFR opcodes to build a tree of forms, questions, and suppression
   conditions.
3. Identifies suppression conditions that are trivially ``TRUE`` (always
   hidden) and optionally patches them.

References
----------
* UEFI Specification §33 (HII) — https://uefi.org/sites/default/files/resources/UEFI_Spec_2_10_Aug29.pdf
* EDK2 ``MdePkg/Include/Uefi/UefiInternalFormRepresentation.h``

Typical usage::

    from hp_bios_tool.secret_menu import SecretMenuUnlocker

    unlocker = SecretMenuUnlocker.from_file("bios.bin")
    hidden = unlocker.find_hidden_items()
    for item in hidden:
        print(item)
    patched = unlocker.unlock_all()
    patched.save("bios_unlocked.bin")
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional

from .utils import find_all, safe_write

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IFR opcode constants (UEFI 2.x)
# ---------------------------------------------------------------------------

class IFROpCode(IntEnum):
    """Selected UEFI IFR opcodes relevant to menu visibility."""

    FORM = 0x01
    SUBTITLE = 0x02
    TEXT = 0x03
    IMAGE = 0x04
    ONE_OF = 0x05
    CHECKBOX = 0x06
    NUMERIC = 0x07
    PASSWORD = 0x08
    ONE_OF_OPTION = 0x09
    SUPPRESS_IF = 0x0A
    LOCKED = 0x0B
    ACTION = 0x0C
    RESET_BUTTON = 0x0D
    FORM_SET = 0x0E
    REF = 0x0F
    NO_SUBMIT_IF = 0x10
    INCONSISTENT_IF = 0x11
    EQ_ID_VAL = 0x12
    EQ_ID_LIST = 0x13
    EQ_ID_ID = 0x14
    EQ_ID_VAL_LIST = 0x15
    AND = 0x16
    OR = 0x17
    NOT = 0x18
    GRAY_OUT_IF = 0x19
    DATE = 0x1A
    TIME = 0x1B
    STRING = 0x1C
    REFRESH = 0x1D
    DISABLE_IF = 0x1E
    ANIMATION = 0x1F
    TO_LOWER = 0x20
    TO_UPPER = 0x21
    MAP = 0x22
    ORDERED_LIST = 0x23
    VARSTORE = 0x24
    VARSTORE_NAME_VALUE = 0x25
    VARSTORE_EFI = 0x26
    VARSTORE_DEVICE = 0x27
    VERSION = 0x28
    END = 0x29
    MATCH = 0x2A
    GET = 0x2B
    SET = 0x2C
    READ = 0x2D
    WRITE = 0x2E
    EQUAL = 0x2F
    NOT_EQUAL = 0x30
    GREATER_THAN = 0x31
    GREATER_EQUAL = 0x32
    LESS_THAN = 0x33
    LESS_EQUAL = 0x34
    BITWISE_AND = 0x35
    BITWISE_OR = 0x36
    BITWISE_NOT = 0x37
    SHIFT_LEFT = 0x38
    SHIFT_RIGHT = 0x39
    ADD = 0x3A
    SUBTRACT = 0x3B
    MULTIPLY = 0x3C
    DIVIDE = 0x3D
    MODULO = 0x3E
    RULE_REF = 0x3F
    QUESTION_REF1 = 0x40
    QUESTION_REF2 = 0x41
    UINT8 = 0x42
    UINT16 = 0x43
    UINT32 = 0x44
    UINT64 = 0x45
    TRUE = 0x46
    FALSE = 0x47
    TO_UINT = 0x48
    TO_STRING = 0x49
    TO_BOOLEAN = 0x4A
    MID = 0x4B
    FIND = 0x4C
    TOKEN = 0x4D
    STRING_REF1 = 0x4E
    STRING_REF2 = 0x4F
    CONDITIONAL = 0x50
    QUESTION_REF3 = 0x51
    ZERO = 0x52
    ONE = 0x53
    ONES = 0x54
    UNDEFINED = 0x55
    LENGTH = 0x56
    DUP = 0x57
    THIS = 0x58
    SPAN = 0x59
    VALUE = 0x5A
    DEFAULT = 0x5B
    DEFAULTSTORE = 0x5C
    FORM_MAP = 0x5D
    CATENATE = 0x5E
    GUID = 0x5F
    SECURITY = 0x60
    MODAL_TAG = 0x61
    REFRESH_ID = 0x62
    WARNING_IF = 0x63
    MATCH2 = 0x64


# ---------------------------------------------------------------------------
# IFR node data-classes
# ---------------------------------------------------------------------------

@dataclass
class IFROpNode:
    """A single decoded IFR operation.

    Attributes:
        offset: Byte offset of this opcode within the IFR buffer.
        opcode: Opcode byte value.
        length: Total size of this opcode (header + payload) in bytes.
        scope_start: True if the ``scope`` bit is set (opens a nested block).
        payload: Raw payload bytes (excluding the 2-byte header).
    """

    offset: int
    opcode: int
    length: int
    scope_start: bool
    payload: bytes

    @property
    def opcode_name(self) -> str:
        try:
            return IFROpCode(self.opcode).name
        except ValueError:
            return f"UNKNOWN_0x{self.opcode:02X}"


@dataclass
class HiddenMenuItem:
    """Describes a form or question that is hidden by a SUPPRESS_IF TRUE.

    Attributes:
        suppress_offset: Offset of the ``SUPPRESS_IF`` opcode.
        condition_offset: Offset of the ``TRUE`` (or always-true) opcode.
        condition_opcode: Opcode byte of the condition (typically 0x46 = TRUE).
        parent_form_name: Name/title of the containing form (best-effort).
        description: Human-readable summary.
    """

    suppress_offset: int
    condition_offset: int
    condition_opcode: int
    parent_form_name: str = ""
    description: str = ""

    def __str__(self) -> str:
        cond_name = IFROpNode(0, self.condition_opcode, 0, False, b"").opcode_name
        return (
            f"HiddenMenuItem @ SUPPRESS_IF=0x{self.suppress_offset:08X}  "
            f"cond={cond_name}@0x{self.condition_offset:08X}  "
            f"form={self.parent_form_name!r}"
        )


# ---------------------------------------------------------------------------
# IFR parser
# ---------------------------------------------------------------------------

class IFRParser:
    """Parses raw IFR data into a flat list of :class:`IFROpNode` objects.

    The IFR byte stream is a sequence of variable-length opcodes::

        Byte 0: opcode
        Byte 1: length (total, including this 2-byte header) | (scope_bit << 7)
        Bytes 2+: payload

    Args:
        data: Raw IFR bytes.
        base_offset: Offset of *data* within the original binary (for reporting).
    """

    SCOPE_BIT = 0x80

    def __init__(self, data: bytes, base_offset: int = 0) -> None:
        self._data = data
        self._base = base_offset

    def parse(self) -> list[IFROpNode]:
        """Return a flat list of all IFR opcodes in the buffer.

        Returns:
            Ordered list of :class:`IFROpNode` objects.
        """
        nodes: list[IFROpNode] = []
        pos = 0
        data = self._data
        length = len(data)

        while pos < length:
            if pos + 2 > length:
                break

            opcode = data[pos]
            raw_len_byte = data[pos + 1]
            scope_start = bool(raw_len_byte & self.SCOPE_BIT)
            op_length = raw_len_byte & ~self.SCOPE_BIT  # lower 7 bits

            # Sanity check
            if op_length < 2 or pos + op_length > length:
                # Try to recover by advancing one byte
                pos += 1
                continue

            payload = data[pos + 2 : pos + op_length]
            nodes.append(IFROpNode(
                offset=self._base + pos,
                opcode=opcode,
                length=op_length,
                scope_start=scope_start,
                payload=payload,
            ))
            pos += op_length

        return nodes


# ---------------------------------------------------------------------------
# HII database locator
# ---------------------------------------------------------------------------

# UEFI HII Package List header starts with a GUID (16 bytes) followed by a
# 4-byte PackageListLength.  We locate IFR data by scanning for the IFR Form
# Set opcode (0x0E) which is almost always present and has a characteristic
# structure.

# A heuristic: look for a GUID + FormSet pattern.  The FormSet opcode header is:
#   0x0E  <length>  <GUID 16 bytes>  <char16 title string>
# The opcode is usually between 20–40 bytes long.

_FORMSET_MIN_SIZE = 20  # bytes including header


def locate_ifr_regions(bios_data: bytes) -> list[tuple[int, int]]:
    """Find candidate IFR regions in a raw BIOS binary.

    Uses a heuristic: scans for ``FORM_SET`` (0x0E) opcode patterns.

    Args:
        bios_data: Raw BIOS image bytes.

    Returns:
        List of ``(offset, estimated_length)`` tuples for each region found.
    """
    regions: list[tuple[int, int]] = []

    for offset in find_all(bios_data, bytes([IFROpCode.FORM_SET])):
        if offset + 2 >= len(bios_data):
            continue

        raw_len = bios_data[offset + 1] & 0x7F
        if raw_len < _FORMSET_MIN_SIZE:
            continue

        # Rough region size: scan forward up to 2 MB for an orphaned END (0x29)
        end = min(offset + 2 * 1024 * 1024, len(bios_data))
        regions.append((offset, end - offset))
        logger.debug("IFR region candidate @ 0x%X", offset)

    # Deduplicate regions that are very close to each other
    merged: list[tuple[int, int]] = []
    for r in sorted(regions):
        if merged and r[0] < merged[-1][0] + 4096:
            continue  # skip duplicates within 4 KB
        merged.append(r)

    return merged


# ---------------------------------------------------------------------------
# Secret menu unlocker
# ---------------------------------------------------------------------------

class SecretMenuUnlocker:
    """Find and optionally remove UEFI IFR suppression conditions.

    Loads a raw BIOS binary, searches for IFR ``SUPPRESS_IF TRUE`` patterns,
    and can patch them to expose hidden menus.

    Args:
        data: Raw BIOS image bytes.
    """

    def __init__(self, data: bytes) -> None:
        self._data = bytearray(data)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "SecretMenuUnlocker":
        """Load a BIOS binary from disk.

        Args:
            path: Path to the ``.bin``, ``.rom``, or ``.fd`` file.

        Returns:
            :class:`SecretMenuUnlocker` instance.
        """
        return cls(Path(path).read_bytes())

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def find_hidden_items(self) -> list[HiddenMenuItem]:
        """Scan the BIOS image for ``SUPPRESS_IF TRUE`` patterns.

        Returns:
            List of :class:`HiddenMenuItem` describing each hidden element.
        """
        hidden: list[HiddenMenuItem] = []
        data = bytes(self._data)

        regions = locate_ifr_regions(data)
        if not regions:
            logger.warning(
                "No IFR FormSet regions found — "
                "image may be compressed or not a UEFI BIOS."
            )
            # Fall back to full-scan with a smaller window
            regions = [(0, len(data))]

        for (region_start, region_len) in regions:
            region_data = data[region_start : region_start + region_len]
            parser = IFRParser(region_data, base_offset=region_start)
            nodes = parser.parse()
            hidden.extend(self._find_suppress_true(nodes, data))

        # Deduplicate by suppress_offset
        seen: set[int] = set()
        unique: list[HiddenMenuItem] = []
        for item in hidden:
            if item.suppress_offset not in seen:
                seen.add(item.suppress_offset)
                unique.append(item)

        logger.info("Found %d hidden/suppressed menu item(s).", len(unique))
        return unique

    @staticmethod
    def _find_suppress_true(
        nodes: list[IFROpNode], full_data: bytes
    ) -> list[HiddenMenuItem]:
        """Identify ``SUPPRESS_IF`` opcodes immediately followed by ``TRUE``.

        The pattern we look for::

            SUPPRESS_IF (0x0A, scope=1)
              TRUE       (0x46, length=2)
              ...nested content...
            END          (0x29)

        Args:
            nodes: Flat IFR node list from :class:`IFRParser`.
            full_data: Complete BIOS bytes (for context).

        Returns:
            List of :class:`HiddenMenuItem`.
        """
        hidden: list[HiddenMenuItem] = []
        current_form_name = ""

        for idx, node in enumerate(nodes):
            # Track form names for better reporting
            if node.opcode == IFROpCode.FORM and len(node.payload) >= 4:
                # FormOp: uint16 FormId, uint16 FormTitle (string token)
                title_token = struct.unpack_from("<H", node.payload, 2)[0]
                current_form_name = f"Form#{node.payload[0]:04X}/Title#{title_token:04X}"

            if node.opcode != IFROpCode.SUPPRESS_IF or not node.scope_start:
                continue

            # Look at the immediately following node
            if idx + 1 >= len(nodes):
                continue

            next_node = nodes[idx + 1]
            condition_is_true = (
                next_node.opcode == IFROpCode.TRUE
                or _is_always_true_condition(next_node)
            )

            if condition_is_true:
                hidden.append(HiddenMenuItem(
                    suppress_offset=node.offset,
                    condition_offset=next_node.offset,
                    condition_opcode=next_node.opcode,
                    parent_form_name=current_form_name,
                    description=(
                        f"SUPPRESS_IF TRUE at 0x{node.offset:08X} "
                        f"(inside {current_form_name!r})"
                    ),
                ))

        return hidden

    # ------------------------------------------------------------------
    # Patching
    # ------------------------------------------------------------------

    def unlock_all(self) -> "SecretMenuUnlocker":
        """Patch all ``SUPPRESS_IF TRUE`` occurrences to ``SUPPRESS_IF FALSE``.

        This changes the suppression condition from "always hide" to "never
        hide", effectively making the previously hidden menu items visible.

        Returns:
            *self* (for chaining), with the BIOS image mutated in-place.
        """
        items = self.find_hidden_items()
        if not items:
            logger.info("No hidden items to unlock.")
            return self

        patched = 0
        for item in items:
            offset = item.condition_offset
            opcode = self._data[offset]

            if opcode == IFROpCode.TRUE:
                # Replace TRUE (0x46) with FALSE (0x47) — same size, trivial patch
                self._data[offset] = IFROpCode.FALSE
                logger.info(
                    "Patched SUPPRESS_IF TRUE → FALSE at 0x%X (%s)",
                    offset,
                    item.parent_form_name,
                )
                patched += 1
            else:
                logger.warning(
                    "Condition at 0x%X is opcode 0x%02X (not TRUE); "
                    "skipping automatic patch.",
                    offset, opcode,
                )

        logger.info("Unlocked %d / %d hidden menu items.", patched, len(items))
        return self

    def unlock_item(self, item: HiddenMenuItem) -> None:
        """Patch a single :class:`HiddenMenuItem`.

        Args:
            item: The item to unlock (patch ``TRUE`` → ``FALSE``).

        Raises:
            ValueError: If the condition opcode is not ``TRUE`` (0x46).
        """
        offset = item.condition_offset
        if self._data[offset] != IFROpCode.TRUE:
            raise ValueError(
                f"Condition at 0x{offset:X} is 0x{self._data[offset]:02X}, "
                "not TRUE (0x46) — cannot auto-patch."
            )
        self._data[offset] = IFROpCode.FALSE
        logger.info("Unlocked item at condition offset 0x%X.", offset)

    def remove_suppress(self, item: HiddenMenuItem) -> None:
        """Remove an entire ``SUPPRESS_IF … END`` block by NOP-filling.

        Fills the ``SUPPRESS_IF`` opcode byte with ``0x29`` (``END``) so that
        the parser sees an immediate close of a non-existent scope, making
        the nested content visible without a condition.

        .. note::
            This is a more aggressive patch.  Use :meth:`unlock_item` (which
            flips ``TRUE`` → ``FALSE``) as the safer alternative.

        Args:
            item: The hidden item to expose.
        """
        # Overwrite the SUPPRESS_IF opcode with an END opcode
        self._data[item.suppress_offset] = IFROpCode.END
        logger.info(
            "Removed SUPPRESS_IF at 0x%X (replaced with END).",
            item.suppress_offset,
        )

    # ------------------------------------------------------------------
    # HP-specific known patches
    # ------------------------------------------------------------------

    def apply_hp_known_patches(self) -> list[str]:
        """Apply a catalogue of HP-specific BIOS secret-menu patches.

        These are binary signatures for well-known hidden menus across HP
        consumer and commercial UEFI BIOSes.  Each patch converts a
        hard-coded ``TRUE`` suppression into ``FALSE``.

        Returns:
            List of human-readable descriptions for every patch applied.
        """
        applied: list[str] = []

        for sig in _HP_KNOWN_SIGNATURES:
            applied.extend(self._apply_signature_patch(sig))

        if not applied:
            logger.info("No HP known-patch signatures matched this BIOS image.")
        else:
            logger.info("Applied %d HP known patch(es).", len(applied))

        return applied

    def _apply_signature_patch(self, sig: "_HPSignature") -> list[str]:
        applied: list[str] = []
        data = bytes(self._data)
        occurrences = list(find_all(data, sig.search_bytes))

        for offset in occurrences:
            patch_offset = offset + sig.patch_relative_offset
            if patch_offset >= len(self._data):
                continue
            current_byte = self._data[patch_offset]
            if current_byte == sig.expected_byte:
                self._data[patch_offset] = sig.patch_byte
                msg = (
                    f"HP known patch '{sig.name}' applied at "
                    f"0x{patch_offset:08X}: "
                    f"0x{current_byte:02X} → 0x{sig.patch_byte:02X}"
                )
                logger.info(msg)
                applied.append(msg)

        return applied

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return the (potentially patched) BIOS image as bytes."""
        return bytes(self._data)

    def save(self, path: str | Path) -> None:
        """Write the patched BIOS image to *path*.

        Args:
            path: Destination file (e.g. ``bios_unlocked.bin``).
        """
        safe_write(Path(path), self.to_bytes())
        logger.info("Patched BIOS saved to %s", path)

    def report(self) -> str:
        """Return a human-readable analysis report for this BIOS image.

        Returns:
            Multi-line report string.
        """
        lines: list[str] = [
            "=" * 60,
            "HP BIOS Secret-Menu Analysis Report",
            f"Image size : {len(self._data):,} bytes (0x{len(self._data):X})",
            "=" * 60,
        ]

        regions = locate_ifr_regions(bytes(self._data))
        lines.append(f"IFR regions found: {len(regions)}")
        for i, (off, sz) in enumerate(regions, 1):
            lines.append(f"  [{i}] offset=0x{off:08X}  size≈{sz:,} bytes")

        hidden = self.find_hidden_items()
        lines.append(f"\nHidden menu items (SUPPRESS_IF TRUE): {len(hidden)}")
        for item in hidden:
            lines.append(f"  {item}")

        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_always_true_condition(node: IFROpNode) -> bool:
    """Return *True* if *node* represents a condition that is always true.

    Beyond the literal ``TRUE`` opcode, some BIOSes use a ``UINT8 0x01`` or
    ``ONE`` opcode as the condition for a ``SUPPRESS_IF``.
    """
    if node.opcode == IFROpCode.TRUE:
        return True
    if node.opcode == IFROpCode.ONE:
        return True
    if node.opcode == IFROpCode.ONES:
        return True
    # UINT8 with value 1
    if node.opcode == IFROpCode.UINT8 and node.payload == b"\x01":
        return True
    return False


# ---------------------------------------------------------------------------
# HP-specific signature database
# ---------------------------------------------------------------------------

@dataclass
class _HPSignature:
    """A byte-signature + patch recipe for a known HP hidden menu."""

    name: str
    search_bytes: bytes
    patch_relative_offset: int
    expected_byte: int     # byte that should be there (TRUE = 0x46)
    patch_byte: int        # byte to write (FALSE = 0x47)


# These signatures are derived from community analysis of HP EliteBook,
# ProBook, and Spectre UEFI BIOSes.  The byte sequences are short IFR
# fragments preceding the SUPPRESS_IF TRUE opcode that guards a hidden menu.
#
# Pattern:  SUPPRESS_IF (0x0A, scope=1)  TRUE (0x46 02)
#           → patch TRUE (0x46) to FALSE (0x47)
#
# The signatures below are illustrative patterns; real deployments may
# fine-tune these for specific BIOS versions.

_HP_KNOWN_SIGNATURES: list[_HPSignature] = [
    # Generic SUPPRESS_IF TRUE pattern (most common)
    _HPSignature(
        name="Generic SUPPRESS_IF TRUE",
        search_bytes=bytes([
            IFROpCode.SUPPRESS_IF,  # 0x0A  ← SUPPRESS_IF with scope
        ]),
        patch_relative_offset=2,    # 0x0A <len+scope> 0x46 ...
        expected_byte=IFROpCode.TRUE,  # 0x46
        patch_byte=IFROpCode.FALSE,    # 0x47
    ),
    # HP Advanced tab suppression pattern
    # Typical: 0x0A 0x82 0x46 0x02 (SUPPRESS_IF scope=1, TRUE, END)
    _HPSignature(
        name="HP Advanced tab suppressor",
        search_bytes=bytes([0x0A, 0x82, 0x46, 0x02]),
        patch_relative_offset=2,
        expected_byte=0x46,
        patch_byte=0x47,
    ),
    # HP security advanced menu suppression
    _HPSignature(
        name="HP Security advanced menu suppressor",
        search_bytes=bytes([0x0A, 0x82, 0x46, 0x02, 0x0F]),
        patch_relative_offset=2,
        expected_byte=0x46,
        patch_byte=0x47,
    ),
    # HP Intel ME / AMT menu suppressor
    _HPSignature(
        name="HP Intel ME/AMT menu suppressor",
        search_bytes=bytes([0x0A, 0x82, 0x46, 0x02, 0x5F]),
        patch_relative_offset=2,
        expected_byte=0x46,
        patch_byte=0x47,
    ),
    # HP OEM manufacturing menu suppressor (often hides Service/MFG options)
    _HPSignature(
        name="HP OEM/Manufacturing menu suppressor",
        search_bytes=bytes([0x1E, 0x82, 0x46, 0x02]),  # DISABLE_IF scope TRUE
        patch_relative_offset=2,
        expected_byte=0x46,
        patch_byte=0x47,
    ),
]
