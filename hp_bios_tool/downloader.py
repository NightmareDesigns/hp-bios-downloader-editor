"""HP SoftPaq BIOS downloader.

Downloads HP BIOS firmware packages from HP's public FTP/catalog infrastructure.

HP maintains a SoftPaq catalog (SDPCatalog.xml or per-platform XML files) at
``https://ftp.hp.com/pub/caps-softpaq/cmdownloads/``.  Individual SoftPaqs
are downloaded from ``https://ftp.hp.com/pub/softpaq/``.

Typical usage::

    from hp_bios_tool.downloader import BIOSDownloader

    dl = BIOSDownloader(output_dir="./bios_files")
    results = dl.search("HP EliteBook 840 G7")
    for r in results:
        print(r)
    dl.download(results[0])
"""

from __future__ import annotations

import logging
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.request import urlretrieve, urlopen
from urllib.error import URLError
from urllib.parse import quote

from .utils import ensure_dir, sha256_file

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HP_CATALOG_URL = (
    "https://ftp.hp.com/pub/caps-softpaq/cmdownloads/SDPCatalog.xml"
)
HP_SOFTPAQ_BASE = "https://ftp.hp.com/pub/softpaq/"
HP_FWUPD_METADATA = "https://fwupd.org/downloads/firmware.xml.gz"

# Category IDs used by HP to identify BIOS updates inside the catalog.
BIOS_CATEGORY_IDS = {"BIOS", "Firmware", "bios", "firmware"}


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------

@dataclass
class SoftPaqEntry:
    """Represents a single HP SoftPaq BIOS entry from the catalog."""

    softpaq_id: str          # e.g. "sp12345"
    name: str                # Human-readable name
    version: str             # BIOS version string
    description: str         # Short description
    category: str            # e.g. "BIOS"
    url: str                 # Direct download URL
    size_bytes: int          # File size in bytes
    md5: str = ""            # Expected MD5 (if provided by catalog)
    sha256: str = ""         # Expected SHA-256 (if provided by catalog)
    supported_models: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        mb = self.size_bytes / 1_048_576
        return (
            f"[{self.softpaq_id}] {self.name} v{self.version}"
            f"  ({mb:.1f} MB)  {self.url}"
        )


# ---------------------------------------------------------------------------
# Downloader
# ---------------------------------------------------------------------------

class BIOSDownloader:
    """Downloads HP BIOS SoftPaq packages.

    Args:
        output_dir: Directory where downloaded files are saved.
        catalog_path: Optional local path to a pre-downloaded SDPCatalog.xml.
            If *None*, the catalog is fetched from HP's servers on first use.
        timeout: Network timeout in seconds (default 30).
    """

    def __init__(
        self,
        output_dir: str | Path = ".",
        catalog_path: Optional[str | Path] = None,
        timeout: int = 30,
    ) -> None:
        self.output_dir = ensure_dir(Path(output_dir))
        self.catalog_path = Path(catalog_path) if catalog_path else None
        self.timeout = timeout
        self._catalog: Optional[ET.Element] = None

    # ------------------------------------------------------------------
    # Catalog management
    # ------------------------------------------------------------------

    def _get_catalog(self) -> ET.Element:
        """Return the parsed SoftPaq catalog XML, downloading it if needed."""
        if self._catalog is not None:
            return self._catalog

        if self.catalog_path and self.catalog_path.exists():
            logger.info("Loading local catalog from %s", self.catalog_path)
            tree = ET.parse(str(self.catalog_path))
        else:
            catalog_file = self.output_dir / "SDPCatalog.xml"
            if catalog_file.exists():
                logger.info("Using cached catalog at %s", catalog_file)
            else:
                logger.info("Downloading HP SoftPaq catalog from %s", HP_CATALOG_URL)
                try:
                    urlretrieve(HP_CATALOG_URL, str(catalog_file))
                except URLError as exc:
                    raise RuntimeError(
                        f"Failed to download HP catalog: {exc}"
                    ) from exc
            tree = ET.parse(str(catalog_file))

        self._catalog = tree.getroot()
        return self._catalog

    def refresh_catalog(self) -> None:
        """Force re-download of the HP SoftPaq catalog."""
        catalog_file = self.output_dir / "SDPCatalog.xml"
        catalog_file.unlink(missing_ok=True)
        self._catalog = None
        logger.info("Catalog cache cleared — will re-download on next use.")

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        category: Optional[str] = None,
        limit: int = 20,
    ) -> list[SoftPaqEntry]:
        """Search the catalog for BIOS SoftPaqs matching *query*.

        Args:
            query: Free-text search string (model name, product number, …).
            category: Optional category filter; defaults to BIOS-related
                categories.
            limit: Maximum number of results to return.

        Returns:
            List of matching :class:`SoftPaqEntry` objects, best matches first.
        """
        root = self._get_catalog()
        needle = query.lower()
        cat_filter = {category.lower()} if category else {c.lower() for c in BIOS_CATEGORY_IDS}

        results: list[SoftPaqEntry] = []
        # SDPCatalog.xml uses <Package> elements
        for pkg in root.iter("Package"):
            cat_el = pkg.find("Category")
            cat_text = (cat_el.text or "").lower() if cat_el is not None else ""
            if cat_filter and cat_text not in cat_filter:
                continue

            name_el = pkg.find("Name")
            name = name_el.text or "" if name_el is not None else ""
            desc_el = pkg.find("Description")
            desc = desc_el.text or "" if desc_el is not None else ""

            searchable = (name + " " + desc).lower()
            if not any(word in searchable for word in needle.split()):
                continue

            entry = self._parse_package(pkg)
            if entry:
                results.append(entry)
            if len(results) >= limit:
                break

        return results

    def search_by_product_id(self, product_id: str) -> list[SoftPaqEntry]:
        """Return BIOS SoftPaqs for the exact HP *product_id* (e.g. ``"G3Z82UA"``).

        Args:
            product_id: HP product identifier (the part before the ``#`` sign).

        Returns:
            List of :class:`SoftPaqEntry` objects.
        """
        root = self._get_catalog()
        pid = product_id.split("#")[0].upper()
        results: list[SoftPaqEntry] = []

        for pkg in root.iter("Package"):
            cat_el = pkg.find("Category")
            cat_text = (cat_el.text or "").lower() if cat_el is not None else ""
            if cat_text not in {c.lower() for c in BIOS_CATEGORY_IDS}:
                continue

            models_el = pkg.find("Systems")
            if models_el is None:
                models_el = pkg.find("SupportedModels")
            models_text = (
                ET.tostring(models_el, encoding="unicode") if models_el is not None else ""
            )
            if pid.lower() not in models_text.lower():
                continue

            entry = self._parse_package(pkg)
            if entry:
                results.append(entry)

        return results

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def download(
        self,
        entry: SoftPaqEntry,
        *,
        verify: bool = True,
    ) -> Path:
        """Download a SoftPaq BIOS package.

        Args:
            entry: The :class:`SoftPaqEntry` to download.
            verify: If *True* and the entry has a SHA-256 hash, verify the
                downloaded file against it.

        Returns:
            Path to the downloaded file.

        Raises:
            RuntimeError: On download failure or hash mismatch.
        """
        filename = entry.url.rsplit("/", 1)[-1]
        dest = self.output_dir / filename

        if dest.exists():
            logger.info("Already downloaded: %s", dest)
        else:
            logger.info("Downloading %s → %s", entry.url, dest)
            try:
                urlretrieve(entry.url, str(dest), reporthook=self._progress_hook)
            except URLError as exc:
                raise RuntimeError(f"Download failed for {entry.url}: {exc}") from exc

        if verify and entry.sha256:
            actual = sha256_file(dest)
            if actual.lower() != entry.sha256.lower():
                dest.unlink(missing_ok=True)
                raise RuntimeError(
                    f"SHA-256 mismatch for {dest.name}:\n"
                    f"  expected: {entry.sha256}\n"
                    f"  got:      {actual}"
                )

        return dest

    def download_by_url(self, url: str, filename: Optional[str] = None) -> Path:
        """Download an arbitrary HP SoftPaq URL.

        Args:
            url: Direct download URL.
            filename: Optional local filename; derived from the URL if omitted.

        Returns:
            Path to the downloaded file.
        """
        name = filename or url.rsplit("/", 1)[-1]
        dest = self.output_dir / name
        if not dest.exists():
            logger.info("Downloading %s → %s", url, dest)
            try:
                urlretrieve(url, str(dest), reporthook=self._progress_hook)
            except URLError as exc:
                raise RuntimeError(f"Download failed: {exc}") from exc
        return dest

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _progress_hook(block_count: int, block_size: int, total_size: int) -> None:
        if total_size > 0:
            done = min(block_count * block_size, total_size)
            pct = done * 100 // total_size
            bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct:3d}%  {done // 1024:,} / {total_size // 1024:,} KB",
                  end="", flush=True)
            if done >= total_size:
                print()

    @staticmethod
    def _parse_package(pkg: ET.Element) -> Optional[SoftPaqEntry]:
        """Parse a ``<Package>`` XML element into a :class:`SoftPaqEntry`."""
        def _text(tag: str) -> str:
            el = pkg.find(tag)
            return (el.text or "").strip() if el is not None else ""

        sp_id = _text("Id") or _text("SoftPaqId") or _text("SoftPaqNumber")
        name = _text("Name") or _text("Title")
        version = _text("Version") or _text("SoftPaqVersion")
        desc = _text("Description")
        category = _text("Category")
        url = _text("Url") or _text("HttpsUrl") or _text("FtpUrl")
        sha256 = _text("SHA256") or _text("Sha256")
        md5 = _text("MD5") or _text("Md5")

        size_str = _text("Size")
        try:
            size_bytes = int(size_str)
        except ValueError:
            size_bytes = 0

        if not url:
            return None

        models: list[str] = []
        for sys_el in pkg.iter("SystemId"):
            if sys_el.text:
                models.append(sys_el.text.strip())

        return SoftPaqEntry(
            softpaq_id=sp_id,
            name=name,
            version=version,
            description=desc,
            category=category,
            url=url,
            size_bytes=size_bytes,
            md5=md5,
            sha256=sha256,
            supported_models=models,
        )


# ---------------------------------------------------------------------------
# SoftPaq extraction helpers
# ---------------------------------------------------------------------------

def extract_softpaq(softpaq_path: Path, dest_dir: Optional[Path] = None) -> Path:
    """Extract an HP SoftPaq ``.exe`` into *dest_dir*.

    HP SoftPaqs are self-extracting archives; this function attempts extraction
    via ``7z`` (p7zip), ``cabextract``, or the ``zipfile`` module (depending on
    the internal format).

    Args:
        softpaq_path: Path to the downloaded ``.exe`` file.
        dest_dir: Directory to extract into; defaults to a sibling directory
            named after the SoftPaq.

    Returns:
        Path to the extraction directory.

    Raises:
        RuntimeError: If no extraction method succeeds.
    """
    import subprocess
    import zipfile

    if dest_dir is None:
        dest_dir = softpaq_path.parent / softpaq_path.stem
    ensure_dir(dest_dir)

    # Try 7z first (handles most SoftPaq formats)
    for cmd in (["7z", "x", str(softpaq_path), f"-o{dest_dir}", "-y"],
                ["7za", "x", str(softpaq_path), f"-o{dest_dir}", "-y"]):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                logger.info("Extracted with 7z → %s", dest_dir)
                return dest_dir
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Try cabextract
    try:
        result = subprocess.run(
            ["cabextract", "-d", str(dest_dir), str(softpaq_path)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            logger.info("Extracted with cabextract → %s", dest_dir)
            return dest_dir
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fall back to zipfile (some SoftPaqs are plain ZIP)
    try:
        with zipfile.ZipFile(softpaq_path) as zf:
            zf.extractall(dest_dir)
        logger.info("Extracted with zipfile → %s", dest_dir)
        return dest_dir
    except zipfile.BadZipFile:
        pass

    raise RuntimeError(
        f"Could not extract {softpaq_path.name}. "
        "Please install 7z (p7zip) or cabextract and retry."
    )


def find_bios_binary(extracted_dir: Path) -> list[Path]:
    """Find candidate BIOS binary files inside an extracted SoftPaq directory.

    Args:
        extracted_dir: Root of an extracted SoftPaq.

    Returns:
        List of paths to likely BIOS binary files (``.bin``, ``.rom``,
        ``.fd``, ``.cap``).
    """
    candidates: list[Path] = []
    patterns = ["*.bin", "*.rom", "*.fd", "*.cap", "*.hpbios"]
    for pattern in patterns:
        candidates.extend(sorted(extracted_dir.rglob(pattern)))
    return candidates
