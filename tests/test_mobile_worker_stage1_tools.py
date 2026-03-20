import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, mock_open


async def _create_tables():
    from lib_webbh.database import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


# ---------------------------------------------------------------------------
# BinaryDownloader tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_binary_downloader_detects_apk_urls():
    await _create_tables()
    from lib_webbh import Target, Asset, get_session
    async with get_session() as session:
        t = Target(company_name="Acme", base_domain="acme.com")
        session.add(t)
        await session.flush()
        a1 = Asset(target_id=t.id, asset_type="url",
                   asset_value="https://cdn.acme.com/app.apk")
        a2 = Asset(target_id=t.id, asset_type="url",
                   asset_value="https://cdn.acme.com/app.ipa")
        a3 = Asset(target_id=t.id, asset_type="url",
                   asset_value="https://acme.com/about")
        session.add_all([a1, a2, a3])
        await session.commit()
        tid = t.id

    from workers.mobile_worker.tools.binary_downloader import BinaryDownloaderTool
    tool = BinaryDownloaderTool()
    urls = await tool._get_binary_urls(tid)
    values = [u[1] for u in urls]
    assert "https://cdn.acme.com/app.apk" in values
    assert "https://cdn.acme.com/app.ipa" in values
    assert "https://acme.com/about" not in values


@pytest.mark.anyio
async def test_binary_downloader_enforces_size_limit():
    """Content-Length > 100MB should be skipped."""
    from workers.mobile_worker.tools.binary_downloader import BinaryDownloaderTool
    tool = BinaryDownloaderTool()
    # 100MB = 104_857_600
    assert tool.MAX_BINARY_SIZE == 104_857_600


@pytest.mark.anyio
async def test_binary_downloader_supports_drop_folder(tmp_path):
    target_dir = tmp_path / "1"
    target_dir.mkdir()
    (target_dir / "manual.apk").write_bytes(b"fake-apk")

    from workers.mobile_worker.tools.binary_downloader import BinaryDownloaderTool
    tool = BinaryDownloaderTool()
    with patch("workers.mobile_worker.base_tool.MOBILE_BINARIES_DIR", str(tmp_path)):
        files = tool._scan_drop_folder(1)
    assert any("manual.apk" in f for f in files)


# ---------------------------------------------------------------------------
# ApktoolDecompiler tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_apktool_decompiler_command_composition():
    from workers.mobile_worker.tools.apktool_decompiler import ApktoolDecompilerTool
    tool = ApktoolDecompilerTool()
    apktool_cmd = tool._build_apktool_cmd("/tmp/test.apk", "/tmp/output")
    assert apktool_cmd[0] == "apktool"
    assert "d" in apktool_cmd
    assert "/tmp/test.apk" in apktool_cmd


@pytest.mark.anyio
async def test_apktool_decompiler_jadx_command():
    from workers.mobile_worker.tools.apktool_decompiler import ApktoolDecompilerTool
    tool = ApktoolDecompilerTool()
    jadx_cmd = tool._build_jadx_cmd("/tmp/test.apk", "/tmp/jadx_output")
    assert jadx_cmd[0] == "jadx"
    assert "/tmp/test.apk" in jadx_cmd


@pytest.mark.anyio
async def test_apktool_decompiler_manifest_parsing():
    from workers.mobile_worker.tools.apktool_decompiler import ApktoolDecompilerTool
    tool = ApktoolDecompilerTool()
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.acme.testapp"
        android:versionCode="10"
        android:versionName="2.1.0">
        <uses-permission android:name="android.permission.INTERNET"/>
        <uses-permission android:name="android.permission.CAMERA"/>
    </manifest>"""
    info = tool._parse_manifest(manifest_xml)
    assert info["package_name"] == "com.acme.testapp"
    assert info["version"] == "2.1.0"
    assert "android.permission.INTERNET" in info["permissions"]
    assert "android.permission.CAMERA" in info["permissions"]


# ---------------------------------------------------------------------------
# MobsfScanner tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_mobsf_scanner_poll_timeout():
    from workers.mobile_worker.tools.mobsf_scanner import MobsfScannerTool
    tool = MobsfScannerTool()
    assert tool.SCAN_TIMEOUT == 600  # 10 minutes


@pytest.mark.anyio
async def test_mobsf_scanner_report_cache_path():
    from workers.mobile_worker.tools.mobsf_scanner import MobsfScannerTool
    tool = MobsfScannerTool()
    path = tool._report_cache_path(1, "com.acme.app")
    assert "com.acme.app_mobsf.json" in path
    assert "/1/" in path
