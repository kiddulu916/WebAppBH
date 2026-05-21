"""Unit tests for CloudStorageAuditor pure helpers (WSTG-CONF-11)."""
import json

from workers.config_mgmt.tools.cloud_storage_auditor import (
    _SECTION_ID,
    _extract_storage_refs,
    _normalize_s3_ref,
    _normalize_azure_ref,
    _normalize_gcs_ref,
)


# ── _SECTION_ID ──────────────────────────────────────────────────────────────

def test_section_id():
    assert _SECTION_ID == "WSTG-CONF-11"


# ── _extract_storage_refs ────────────────────────────────────────────────────

def test_extract_s3_virtual_hosted():
    body = "Check https://my-bucket.s3.amazonaws.com/file.txt for assets"
    result = _extract_storage_refs(body, "s3")
    assert any("my-bucket" in r for r in result)


def test_extract_s3_with_region():
    body = "https://my-bucket.s3.us-east-1.amazonaws.com/key"
    result = _extract_storage_refs(body, "s3")
    assert any("my-bucket" in r for r in result)


def test_extract_s3_path_style():
    body = "stored at https://s3.amazonaws.com/my-bucket/key"
    result = _extract_storage_refs(body, "s3")
    assert any("my-bucket" in r for r in result)


def test_extract_azure_blob():
    body = "https://myaccount.blob.core.windows.net/mycontainer/file"
    result = _extract_storage_refs(body, "azure")
    assert any("myaccount" in r for r in result)


def test_extract_azure_file_service():
    body = "https://myaccount.file.core.windows.net/share"
    result = _extract_storage_refs(body, "azure")
    assert any("myaccount" in r for r in result)


def test_extract_gcs_googleapis():
    body = "https://storage.googleapis.com/my-gcs-bucket/key"
    result = _extract_storage_refs(body, "gcs")
    assert any("my-gcs-bucket" in r for r in result)


def test_extract_gcs_subdomain():
    body = "https://my-gcs-bucket.storage.googleapis.com/key"
    result = _extract_storage_refs(body, "gcs")
    assert any("my-gcs-bucket" in r for r in result)


def test_extract_no_match_returns_empty():
    body = "Nothing cloud-related here, just a normal webpage."
    assert _extract_storage_refs(body, "s3") == []
    assert _extract_storage_refs(body, "azure") == []
    assert _extract_storage_refs(body, "gcs") == []


def test_extract_multiple_s3_refs():
    body = "bucket1.s3.amazonaws.com and bucket2.s3.amazonaws.com"
    result = _extract_storage_refs(body, "s3")
    assert len(result) == 2


# ── _normalize_s3_ref ─────────────────────────────────────────────────────────

def test_normalize_s3_virtual_hosted_with_region():
    result = _normalize_s3_ref("my-bucket.s3.us-east-1.amazonaws.com")
    assert result is not None
    assert result[0] == "my-bucket"
    assert result[1] == "us-east-1"


def test_normalize_s3_virtual_hosted_no_region():
    result = _normalize_s3_ref("my-bucket.s3.amazonaws.com")
    assert result is not None
    assert result[0] == "my-bucket"
    assert result[1] is None


def test_normalize_s3_path_style():
    result = _normalize_s3_ref("s3.amazonaws.com/my-bucket")
    assert result is not None
    assert result[0] == "my-bucket"


def test_normalize_s3_website_endpoint():
    result = _normalize_s3_ref("my-bucket.s3-website-us-east-1.amazonaws.com")
    assert result is not None
    assert result[0] == "my-bucket"


def test_normalize_s3_invalid_returns_none():
    assert _normalize_s3_ref("not-a-bucket") is None
    assert _normalize_s3_ref("") is None


# ── _normalize_azure_ref ──────────────────────────────────────────────────────

def test_normalize_azure_with_container():
    result = _normalize_azure_ref("myaccount.blob.core.windows.net/mycontainer")
    assert result is not None
    assert result[0] == "myaccount"
    assert result[1] == "mycontainer"


def test_normalize_azure_no_container():
    result = _normalize_azure_ref("myaccount.blob.core.windows.net")
    assert result is not None
    assert result[0] == "myaccount"
    assert result[1] is None


def test_normalize_azure_file_service():
    result = _normalize_azure_ref("myaccount.file.core.windows.net")
    assert result is not None
    assert result[0] == "myaccount"


def test_normalize_azure_queue_service():
    result = _normalize_azure_ref("myaccount.queue.core.windows.net")
    assert result is not None
    assert result[0] == "myaccount"


def test_normalize_azure_invalid_returns_none():
    assert _normalize_azure_ref("not-azure.example.com") is None
    assert _normalize_azure_ref("") is None


# ── _normalize_gcs_ref ────────────────────────────────────────────────────────

def test_normalize_gcs_storage_googleapis():
    result = _normalize_gcs_ref("storage.googleapis.com/my-gcs-bucket")
    assert result == "my-gcs-bucket"


def test_normalize_gcs_subdomain_style():
    result = _normalize_gcs_ref("my-gcs-bucket.storage.googleapis.com")
    assert result == "my-gcs-bucket"


def test_normalize_gcs_cloud_google():
    result = _normalize_gcs_ref("storage.cloud.google.com/my-gcs-bucket")
    assert result == "my-gcs-bucket"


def test_normalize_gcs_invalid_returns_none():
    assert _normalize_gcs_ref("notgcs.example.com") is None
    assert _normalize_gcs_ref("") is None


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_extract_unknown_provider_returns_empty():
    body = "my-bucket.s3.amazonaws.com"
    assert _extract_storage_refs(body, "gcp") == []
    assert _extract_storage_refs(body, "") == []


def test_normalize_s3_mixed_case():
    result = _normalize_s3_ref("MY-BUCKET.S3.AMAZONAWS.COM")
    assert result is not None
    assert result[0] == "my-bucket"


def test_normalize_azure_mixed_case():
    result = _normalize_azure_ref("MYACCOUNT.BLOB.CORE.WINDOWS.NET")
    assert result is not None
    assert result[0] == "myaccount"
