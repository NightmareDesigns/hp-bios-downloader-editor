"""Tests for hp_bios_tool.downloader (catalog parsing, offline)."""

import xml.etree.ElementTree as ET
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from hp_bios_tool.downloader import (
    BIOSDownloader,
    SoftPaqEntry,
    find_bios_binary,
    extract_softpaq,
)


# ---------------------------------------------------------------------------
# Minimal SDPCatalog XML for offline tests
# ---------------------------------------------------------------------------

SAMPLE_CATALOG_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<NewDataSet>
  <Package>
    <Id>sp99001</Id>
    <Name>HP EliteBook 840 G7 BIOS</Name>
    <Version>T76 Ver. 01.15.00</Version>
    <Description>HP BIOS Update for EliteBook 840 G7</Description>
    <Category>BIOS</Category>
    <Url>https://ftp.hp.com/pub/softpaq/sp99001-99500/sp99001.exe</Url>
    <Size>14000000</Size>
    <SHA256>abc123def456abc123def456abc123def456abc123def456abc123def456abc1</SHA256>
    <Systems>
      <SystemId>8YH28AV</SystemId>
      <SystemId>G3Z82UA</SystemId>
    </Systems>
  </Package>
  <Package>
    <Id>sp99002</Id>
    <Name>HP ProBook 450 G8 BIOS Update</Name>
    <Version>S78 Ver. 01.10.00</Version>
    <Description>HP BIOS for ProBook 450 G8</Description>
    <Category>BIOS</Category>
    <Url>https://ftp.hp.com/pub/softpaq/sp99001-99500/sp99002.exe</Url>
    <Size>12000000</Size>
    <SHA256></SHA256>
    <Systems>
      <SystemId>3G2D4AV</SystemId>
    </Systems>
  </Package>
  <Package>
    <Id>sp99003</Id>
    <Name>HP EliteBook 840 G7 Network Driver</Name>
    <Version>1.0</Version>
    <Description>Network driver (not BIOS)</Description>
    <Category>Network</Category>
    <Url>https://ftp.hp.com/pub/softpaq/sp99001-99500/sp99003.exe</Url>
    <Size>5000000</Size>
    <SHA256></SHA256>
    <Systems/>
  </Package>
</NewDataSet>
"""


@pytest.fixture
def catalog_file(tmp_path):
    """Write sample catalog XML to a temp file and return the path."""
    f = tmp_path / "SDPCatalog.xml"
    f.write_text(SAMPLE_CATALOG_XML, encoding="utf-8")
    return f


@pytest.fixture
def downloader(tmp_path, catalog_file):
    """Return a BIOSDownloader using the sample catalog."""
    return BIOSDownloader(output_dir=tmp_path, catalog_path=catalog_file)


# ---------------------------------------------------------------------------
# SoftPaqEntry
# ---------------------------------------------------------------------------

class TestSoftPaqEntry:
    def test_str_includes_id_and_version(self):
        entry = SoftPaqEntry(
            softpaq_id="sp99001",
            name="HP BIOS",
            version="01.15.00",
            description="Test",
            category="BIOS",
            url="https://example.com/sp99001.exe",
            size_bytes=14_000_000,
        )
        s = str(entry)
        assert "sp99001" in s
        assert "01.15.00" in s
        assert "MB" in s


# ---------------------------------------------------------------------------
# BIOSDownloader — catalog loading
# ---------------------------------------------------------------------------

class TestCatalogLoading:
    def test_loads_local_catalog(self, downloader):
        root = downloader._get_catalog()
        assert root is not None

    def test_catalog_cached(self, downloader):
        root1 = downloader._get_catalog()
        root2 = downloader._get_catalog()
        assert root1 is root2  # same object (cached)

    def test_refresh_clears_cache(self, downloader):
        downloader._get_catalog()
        assert downloader._catalog is not None
        downloader.refresh_catalog()
        assert downloader._catalog is None


# ---------------------------------------------------------------------------
# BIOSDownloader — search
# ---------------------------------------------------------------------------

class TestSearch:
    def test_search_finds_bios(self, downloader):
        results = downloader.search("EliteBook 840")
        assert len(results) >= 1
        assert all(r.category.lower() in {"bios", "firmware"} for r in results)

    def test_search_filters_non_bios(self, downloader):
        results = downloader.search("Network")
        # "Network" matches sp99003 which is category "Network", not BIOS
        assert all(r.softpaq_id != "sp99003" for r in results)

    def test_search_returns_correct_entry(self, downloader):
        results = downloader.search("ProBook 450")
        assert any(r.softpaq_id == "sp99002" for r in results)

    def test_search_no_match(self, downloader):
        results = downloader.search("xyz_nonexistent_model_12345")
        assert results == []

    def test_search_limit(self, downloader):
        results = downloader.search("HP", limit=1)
        assert len(results) <= 1

    def test_search_url_populated(self, downloader):
        from urllib.parse import urlparse
        results = downloader.search("EliteBook 840")
        for r in results:
            parsed = urlparse(r.url)
            assert parsed.netloc == "ftp.hp.com", (
                f"Expected HP FTP host, got {parsed.netloc!r} in URL {r.url!r}"
            )

    def test_search_size_populated(self, downloader):
        results = downloader.search("EliteBook 840")
        assert all(r.size_bytes > 0 for r in results)


class TestSearchByProductId:
    def test_finds_by_product_id(self, downloader):
        results = downloader.search_by_product_id("G3Z82UA")
        assert any(r.softpaq_id == "sp99001" for r in results)

    def test_ignores_hash_suffix(self, downloader):
        results = downloader.search_by_product_id("G3Z82UA#ABA")
        assert any(r.softpaq_id == "sp99001" for r in results)

    def test_no_match(self, downloader):
        results = downloader.search_by_product_id("XXXXXXX")
        assert results == []


# ---------------------------------------------------------------------------
# BIOSDownloader — download (mocked)
# ---------------------------------------------------------------------------

class TestDownload:
    def test_download_creates_file(self, downloader, tmp_path):
        entry = SoftPaqEntry(
            softpaq_id="sp99001",
            name="Test BIOS",
            version="1.0",
            description="",
            category="BIOS",
            url="https://example.com/sp99001.exe",
            size_bytes=100,
        )

        dummy_content = b"DUMMY_BIOS_FILE_DATA"

        def fake_urlretrieve(url, dest, reporthook=None):
            Path(dest).write_bytes(dummy_content)

        with patch("hp_bios_tool.downloader.urlretrieve", side_effect=fake_urlretrieve):
            result = downloader.download(entry, verify=False)

        assert result.exists()
        assert result.read_bytes() == dummy_content

    def test_download_skips_if_exists(self, downloader, tmp_path):
        existing = tmp_path / "sp99001.exe"
        existing.write_bytes(b"ALREADY_THERE")

        entry = SoftPaqEntry(
            softpaq_id="sp99001",
            name="Test BIOS",
            version="1.0",
            description="",
            category="BIOS",
            url="https://example.com/sp99001.exe",
            size_bytes=100,
        )

        with patch("hp_bios_tool.downloader.urlretrieve") as mock_dl:
            downloader.download(entry, verify=False)
            mock_dl.assert_not_called()

    def test_download_raises_on_url_error(self, downloader):
        from urllib.error import URLError
        entry = SoftPaqEntry(
            softpaq_id="sp_err",
            name="",
            version="",
            description="",
            category="BIOS",
            url="https://bad.example.com/missing.exe",
            size_bytes=0,
        )
        with patch("hp_bios_tool.downloader.urlretrieve", side_effect=URLError("timeout")):
            with pytest.raises(RuntimeError, match="Download failed"):
                downloader.download(entry, verify=False)


# ---------------------------------------------------------------------------
# find_bios_binary
# ---------------------------------------------------------------------------

class TestFindBiosBinary:
    def test_finds_bin_file(self, tmp_path):
        bios = tmp_path / "firmware.bin"
        bios.write_bytes(b"\x00" * 10)
        results = find_bios_binary(tmp_path)
        assert bios in results

    def test_finds_rom_file(self, tmp_path):
        rom = tmp_path / "bios.rom"
        rom.write_bytes(b"\x00" * 10)
        results = find_bios_binary(tmp_path)
        assert rom in results

    def test_ignores_txt_files(self, tmp_path):
        txt = tmp_path / "readme.txt"
        txt.write_text("hello")
        results = find_bios_binary(tmp_path)
        assert txt not in results

    def test_finds_nested(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        bios = sub / "bios.fd"
        bios.write_bytes(b"\x00" * 8)
        results = find_bios_binary(tmp_path)
        assert bios in results

    def test_empty_dir(self, tmp_path):
        results = find_bios_binary(tmp_path)
        assert results == []
