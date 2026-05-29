"""Command-line interface for the HP BIOS tool.

Entry points
------------
``hp-bios`` — installed by ``setup.py`` / ``pyproject.toml``

Subcommands
-----------
``download``     Search and download HP BIOS SoftPaq packages.
``edit``         Parse and modify HP BIOS REPSET configuration files.
``unlock``       Scan a BIOS binary for hidden menus and patch them.
``hexdump``      Dump a region of a BIOS binary file.
``info``         Print information and analysis about a BIOS binary.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=level,
    )


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_download(args: argparse.Namespace) -> int:
    """Handle the ``download`` subcommand."""
    from .downloader import BIOSDownloader, extract_softpaq, find_bios_binary
    from .system_info import detect_local_system

    dl = BIOSDownloader(output_dir=args.output_dir, timeout=args.timeout)

    if args.url:
        dest = dl.download_by_url(args.url)
        print(f"Downloaded: {dest}")
        if args.extract:
            extracted = extract_softpaq(dest)
            bins = find_bios_binary(extracted)
            print(f"Extracted to: {extracted}")
            for b in bins:
                print(f"  BIOS binary: {b}")
        return 0

    if args.this_pc:
        if args.product_id or args.query or args.url:
            print(
                "ERROR: --this-pc cannot be combined with --query, --product-id, or --url.",
                file=sys.stderr,
            )
            return 1
        system = detect_local_system()
        print(f"Detected system: {system}")
        if not system.is_hp:
            print("ERROR: Auto-detection only supports HP systems.", file=sys.stderr)
            return 1

        results = []
        if system.product_id:
            print(f"Searching BIOS catalog by product ID: {system.product_id}")
            results = dl.search_by_product_id(system.product_id)
        if not results and system.product_name:
            if system.product_id:
                print("No exact product-ID match found; falling back to model search.")
            print(f"Searching BIOS catalog by model: {system.product_name}")
            results = dl.search(system.product_name, limit=args.limit)
        if not results:
            print("No matching SoftPaqs found.")
            return 0
    elif args.product_id:
        results = dl.search_by_product_id(args.product_id)
    elif args.query:
        results = dl.search(args.query, limit=args.limit)
    else:
        print("ERROR: Provide --query, --product-id, --url, or --this-pc.", file=sys.stderr)
        return 1

    if not results:
        print("No matching SoftPaqs found.")
        return 0

    for i, entry in enumerate(results, 1):
        print(f"  [{i:2d}] {entry}")

    if args.download_first or args.all:
        to_download = results if args.all else results[:1]
        for entry in to_download:
            dest = dl.download(entry)
            print(f"Downloaded: {dest}")
            if args.extract:
                extracted = extract_softpaq(dest)
                bins = find_bios_binary(extracted)
                print(f"Extracted to: {extracted}")
                for b in bins:
                    print(f"  BIOS binary: {b}")

    return 0


def cmd_edit(args: argparse.Namespace) -> int:
    """Handle the ``edit`` subcommand."""
    from .editor import BIOSConfigEditor

    editor = BIOSConfigEditor.from_file(args.input)

    if args.list:
        for s in editor.list_settings():
            marker = "* " if not args.show_options else ""
            print(f"{marker}{s.name} = {s.selected!r}")
            if args.show_options:
                for opt in s.options:
                    prefix = "  *" if opt == s.selected else "   "
                    print(f"{prefix} {opt}")

    if args.find:
        matches = editor.find(args.find)
        for s in matches:
            print(f"  {s.name} = {s.selected!r}  options={s.options}")

    if args.set:
        for pair in args.set:
            try:
                name, value = pair.split("=", 1)
            except ValueError:
                print(f"ERROR: --set expects 'Name=Value', got {pair!r}", file=sys.stderr)
                return 1
            try:
                editor.set(name.strip(), value.strip())
            except (KeyError, ValueError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

    if args.output:
        editor.save(args.output)
        print(f"Saved → {args.output}")
    elif args.set:
        # Print modified config to stdout if no output file given
        print(editor.to_text())

    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    """Handle the ``unlock`` subcommand."""
    from .secret_menu import SecretMenuUnlocker

    print(f"Loading BIOS image: {args.input}")
    unlocker = SecretMenuUnlocker.from_file(args.input)

    if args.report:
        print(unlocker.report())
        return 0

    hidden = unlocker.find_hidden_items()

    if not hidden:
        print("No SUPPRESS_IF TRUE patterns found in this BIOS image.")
        print("The image may be compressed, or this BIOS has no hidden menus.")
        return 0

    print(f"Found {len(hidden)} hidden/suppressed menu item(s):")
    for i, item in enumerate(hidden, 1):
        print(f"  [{i:2d}] {item}")

    if args.dry_run:
        print("\nDry run — no changes written.")
        return 0

    if args.hp_patches:
        applied = unlocker.apply_hp_known_patches()
        for msg in applied:
            print(f"  Applied: {msg}")

    unlocker.unlock_all()

    output = args.output or (Path(args.input).stem + "_unlocked" + Path(args.input).suffix)
    unlocker.save(output)
    print(f"\nPatched BIOS saved → {output}")
    print("⚠  Flash at your own risk. Always keep the original backup.")
    return 0


def cmd_hexdump(args: argparse.Namespace) -> int:
    """Handle the ``hexdump`` subcommand."""
    from .utils import hex_dump

    data = Path(args.input).read_bytes()
    offset = int(args.offset, 0) if args.offset else 0
    length = int(args.length, 0) if args.length else 256

    print(hex_dump(data[offset : offset + length], start_offset=offset))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Handle the ``info`` subcommand."""
    from .secret_menu import SecretMenuUnlocker, locate_ifr_regions
    from .utils import md5_file, sha256_file

    path = Path(args.input)
    data = path.read_bytes()

    print(f"File   : {path}")
    print(f"Size   : {len(data):,} bytes  (0x{len(data):X})")
    print(f"MD5    : {md5_file(path)}")
    print(f"SHA256 : {sha256_file(path)}")

    regions = locate_ifr_regions(data)
    print(f"\nIFR regions detected: {len(regions)}")
    for off, sz in regions:
        print(f"  offset=0x{off:08X}  size≈{sz:,} bytes")

    if args.find_hidden:
        unlocker = SecretMenuUnlocker(data)
        hidden = unlocker.find_hidden_items()
        print(f"\nHidden menu items (SUPPRESS_IF TRUE): {len(hidden)}")
        for item in hidden:
            print(f"  {item}")

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hp-bios",
        description=(
            "NightmareDesigns HP BIOS Downloader, Editor & Secret-Menu Unlocker\n"
            "─────────────────────────────────────────────────────────────────\n"
            "download : fetch HP BIOS SoftPaq packages\n"
            "edit     : parse / modify HP BIOS REPSET config files\n"
            "unlock   : expose hidden BIOS menus by patching IFR suppression\n"
            "hexdump  : dump a region of a BIOS binary\n"
            "info     : inspect a BIOS binary file\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose debug output.")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── download ──────────────────────────────────────────────────────────
    dl_p = sub.add_parser("download", help="Search and download HP BIOS SoftPaqs.")
    dl_p.add_argument("-q", "--query", metavar="TEXT",
                      help="Free-text search query (model name, etc.).")
    dl_p.add_argument("-p", "--product-id", metavar="PRODUCT",
                      help="HP product ID (e.g. G3Z82UA).")
    dl_p.add_argument("-u", "--url", metavar="URL",
                      help="Direct SoftPaq download URL.")
    dl_p.add_argument("--this-pc", action="store_true",
                      help="Auto-detect this HP system and fetch its matching BIOS.")
    dl_p.add_argument("-o", "--output-dir", default=".", metavar="DIR",
                      help="Directory to save downloads (default: current dir).")
    dl_p.add_argument("--limit", type=int, default=10,
                      help="Maximum search results to show (default: 10).")
    dl_p.add_argument("--download-first", action="store_true",
                      help="Download the top search result.")
    dl_p.add_argument("--all", action="store_true",
                      help="Download all matching search results.")
    dl_p.add_argument("--extract", action="store_true",
                      help="Extract the downloaded SoftPaq after download.")
    dl_p.add_argument("--timeout", type=int, default=30,
                      help="Network timeout in seconds (default: 30).")

    # ── edit ──────────────────────────────────────────────────────────────
    ed_p = sub.add_parser("edit", help="Edit HP BIOS REPSET configuration files.")
    ed_p.add_argument("input", metavar="CONFIG.REPSET",
                      help="Input REPSET configuration file.")
    ed_p.add_argument("-o", "--output", metavar="OUT.REPSET",
                      help="Output file (prints to stdout if omitted).")
    ed_p.add_argument("-l", "--list", action="store_true",
                      help="List all settings and their current values.")
    ed_p.add_argument("--show-options", action="store_true",
                      help="Show all allowed values for each setting (with --list).")
    ed_p.add_argument("-f", "--find", metavar="REGEX",
                      help="Show settings whose names match REGEX.")
    ed_p.add_argument("-s", "--set", nargs="+", metavar="Name=Value",
                      help="Set one or more settings (e.g. 'USB Legacy Support=Disabled').")

    # ── unlock ────────────────────────────────────────────────────────────
    ul_p = sub.add_parser(
        "unlock",
        help="Unlock hidden BIOS menus by patching IFR suppression conditions.",
    )
    ul_p.add_argument("input", metavar="BIOS.bin",
                      help="Raw BIOS binary file.")
    ul_p.add_argument("-o", "--output", metavar="OUT.bin",
                      help="Output file (defaults to <input>_unlocked.bin).")
    ul_p.add_argument("--report", action="store_true",
                      help="Print analysis report only; do not patch.")
    ul_p.add_argument("--dry-run", action="store_true",
                      help="Show what would be patched without writing changes.")
    ul_p.add_argument("--hp-patches", action="store_true",
                      help="Also apply HP-specific known signature patches.")

    # ── hexdump ───────────────────────────────────────────────────────────
    hd_p = sub.add_parser("hexdump", help="Hex-dump a region of a BIOS binary.")
    hd_p.add_argument("input", metavar="FILE",
                      help="Binary file to dump.")
    hd_p.add_argument("--offset", metavar="OFFSET",
                      help="Start offset (decimal or 0x hex, default 0).")
    hd_p.add_argument("--length", metavar="LENGTH",
                      help="Number of bytes to dump (default 256).")

    # ── info ──────────────────────────────────────────────────────────────
    in_p = sub.add_parser("info", help="Display info about a BIOS binary file.")
    in_p.add_argument("input", metavar="BIOS.bin",
                      help="BIOS binary file.")
    in_p.add_argument("--find-hidden", action="store_true",
                      help="Scan for hidden menus and list them.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Exit code (0 = success).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    handlers = {
        "download": cmd_download,
        "edit": cmd_edit,
        "unlock": cmd_unlock,
        "hexdump": cmd_hexdump,
        "info": cmd_info,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        logging.error("%s", exc)
        if hasattr(args, "verbose") and args.verbose:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
