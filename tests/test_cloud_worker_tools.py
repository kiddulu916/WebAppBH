"""Tests for cloud_worker tools."""

import os

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_cloud_worker_concurrency_weight_classes():
    from workers.cloud_worker.concurrency import WeightClass

    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"


def test_cloud_worker_concurrency_get_semaphore():
    from workers.cloud_worker.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.HEAVY)
    assert sem is not None


def test_cloud_test_tool_is_abstract():
    import inspect
    from workers.cloud_worker.base_tool import CloudTestTool

    assert inspect.isabstract(CloudTestTool)


def test_cloud_test_tool_provider_detection():
    from workers.cloud_worker.base_tool import detect_provider

    assert detect_provider("https://mybucket.s3.amazonaws.com") == "aws"
    assert detect_provider("https://myaccount.blob.core.windows.net/container") == "azure"
    assert detect_provider("https://storage.googleapis.com/mybucket") == "gcp"
    assert detect_provider("https://myapp.appspot.com") == "gcp"
    assert detect_provider("https://myapp.firebaseio.com") == "gcp"
    assert detect_provider("https://example.com") is None


CLOUD_URL_PATTERNS_FOR_TEST = [
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "storage.googleapis.com",
    "appspot.com",
    "firebaseio.com",
]


def test_cloud_url_patterns_exported():
    from workers.cloud_worker.base_tool import CLOUD_URL_PATTERNS

    for pattern in CLOUD_URL_PATTERNS_FOR_TEST:
        assert any(pattern in p for p in CLOUD_URL_PATTERNS)


# ===================================================================
# AssetScraperTool tests
# ===================================================================

def test_asset_scraper_classify_url():
    from workers.cloud_worker.tools.asset_scraper import AssetScraperTool

    tool = AssetScraperTool()
    assert tool.classify_url("https://mybucket.s3.amazonaws.com") == ("aws", "s3_bucket")
    assert tool.classify_url("https://myaccount.blob.core.windows.net/container") == ("azure", "blob_container")
    assert tool.classify_url("https://storage.googleapis.com/mybucket") == ("gcp", "gcs_bucket")
    assert tool.classify_url("https://myapp.firebaseio.com") == ("gcp", "firebase_db")
    assert tool.classify_url("https://myapp.appspot.com") == ("gcp", "appspot")
    assert tool.classify_url("https://example.com") is None


def test_asset_scraper_dedup_urls():
    from workers.cloud_worker.tools.asset_scraper import AssetScraperTool

    tool = AssetScraperTool()
    urls = [
        "https://mybucket.s3.amazonaws.com",
        "https://mybucket.s3.amazonaws.com",  # duplicate
        "https://other.s3.amazonaws.com",
    ]
    deduped = tool.deduplicate(urls)
    assert len(deduped) == 2


# ===================================================================
# CloudEnumTool tests
# ===================================================================

SAMPLE_CLOUD_ENUM_OUTPUT = """
[+] Checking for S3 Buckets
[+] Found open S3 bucket: acme-backup.s3.amazonaws.com
[+] Found open S3 bucket: acme-assets.s3.amazonaws.com
[+] Checking for Azure Blobs
[+] Found open Azure container: acme.blob.core.windows.net/public
[+] Checking for GCP Buckets
[+] Found open GCP bucket: storage.googleapis.com/acme-data
"""


def test_cloud_enum_parse_output():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    results = tool.parse_output(SAMPLE_CLOUD_ENUM_OUTPUT)
    assert len(results) == 4
    assert any("acme-backup.s3.amazonaws.com" in r for r in results)
    assert any("blob.core.windows.net" in r for r in results)
    assert any("storage.googleapis.com" in r for r in results)


def test_cloud_enum_parse_output_empty():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    results = tool.parse_output("")
    assert results == []


def test_cloud_enum_build_command():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    cmd = tool.build_command("acme.com", mutations=["corp", "dev"])
    assert "cloud_enum" in cmd[0] or "cloud_enum" in " ".join(cmd)
    assert "-k" in cmd
    assert "acme.com" in cmd


from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.anyio
async def test_cloud_enum_skips_on_cooldown():
    from workers.cloud_worker.tools.cloud_enum import CloudEnumTool

    tool = CloudEnumTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True


# ===================================================================
# BucketProberTool tests
# ===================================================================

def test_bucket_prober_extract_s3_bucket_name():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    assert tool.extract_bucket_name("https://mybucket.s3.amazonaws.com", "aws") == "mybucket"
    assert tool.extract_bucket_name("https://s3.amazonaws.com/mybucket", "aws") == "mybucket"
    assert tool.extract_bucket_name("https://mybucket.s3.us-west-2.amazonaws.com", "aws") == "mybucket"


def test_bucket_prober_extract_azure_container():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    name = tool.extract_bucket_name(
        "https://myaccount.blob.core.windows.net/mycontainer", "azure"
    )
    assert name == "mycontainer"


def test_bucket_prober_extract_gcs_bucket_name():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    assert tool.extract_bucket_name("https://storage.googleapis.com/mybucket", "gcp") == "mybucket"


def test_bucket_prober_severity_for_permissions():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    assert tool.severity_for_access("write") == "critical"
    assert tool.severity_for_access("read") == "high"
    assert tool.severity_for_access("list") == "high"
    assert tool.severity_for_access("none") == "info"


@pytest.mark.anyio
async def test_bucket_prober_skips_on_cooldown():
    from workers.cloud_worker.tools.bucket_prober import BucketProberTool

    tool = BucketProberTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True


# ===================================================================
# FileListerTool tests
# ===================================================================

def test_file_lister_sensitive_patterns():
    from workers.cloud_worker.tools.file_lister import FileListerTool

    tool = FileListerTool()
    assert tool.is_sensitive("backup.sql") is True
    assert tool.is_sensitive(".env") is True
    assert tool.is_sensitive("id_rsa.pem") is True
    assert tool.is_sensitive("credentials.json") is True
    assert tool.is_sensitive("server.key") is True
    assert tool.is_sensitive(".htpasswd") is True
    assert tool.is_sensitive("db_dump.bak") is True
    assert tool.is_sensitive("index.html") is False
    assert tool.is_sensitive("logo.png") is False


def test_file_lister_severity_for_file():
    from workers.cloud_worker.tools.file_lister import FileListerTool

    tool = FileListerTool()
    assert tool.severity_for_file("private.pem") == "critical"
    assert tool.severity_for_file("server.key") == "critical"
    assert tool.severity_for_file("id_rsa") == "critical"
    assert tool.severity_for_file(".env") == "high"
    assert tool.severity_for_file("credentials.json") == "high"
    assert tool.severity_for_file("dump.sql") == "high"
    assert tool.severity_for_file("config.yml") == "medium"
    assert tool.severity_for_file("export.csv") == "medium"


@pytest.mark.anyio
async def test_file_lister_skips_on_cooldown():
    from workers.cloud_worker.tools.file_lister import FileListerTool

    tool = FileListerTool()
    with patch.object(tool, "check_cooldown", new_callable=AsyncMock, return_value=True):
        result = await tool.execute(
            target=MagicMock(target_profile={}),
            scope_manager=MagicMock(),
            target_id=1,
            container_name="test",
        )
    assert result.get("skipped_cooldown") is True
