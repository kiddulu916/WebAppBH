"""Unit tests for CloudStorageAuditor pure helpers (WSTG-CONF-11)."""
import json

from workers.config_mgmt.tools.cloud_storage_auditor import (
    _SECTION_ID,
    _extract_storage_refs,
    _normalize_s3_ref,
    _normalize_azure_ref,
    _normalize_gcs_ref,
    _parse_s3scanner_output,
    _classify_s3scanner_result,
    _parse_cloud_enum_output,
    _parse_azcopy_output,
    _classify_azure_probe,
)

_AZURE_URL = "https://myaccount.blob.core.windows.net/mycontainer"


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


# ── _parse_s3scanner_output ───────────────────────────────────────────────────

def test_parse_s3scanner_empty_returns_empty():
    assert _parse_s3scanner_output("") == []


def test_parse_s3scanner_malformed_json_returns_empty():
    assert _parse_s3scanner_output("not json {{{{") == []


def test_parse_s3scanner_writable_bucket():
    data = json.dumps([{
        "name": "test-bucket",
        "exists": True,
        "objects_listable": True,
        "objects_readable": True,
        "objects_writable": True,
    }])
    result = _parse_s3scanner_output(data)
    assert len(result) == 1
    assert result[0]["bucket"] == "test-bucket"
    assert result[0]["exists"] is True
    assert result[0]["listable"] is True
    assert result[0]["readable"] is True
    assert result[0]["writable"] is True


def test_parse_s3scanner_nonexistent_bucket():
    data = json.dumps([{
        "name": "ghost-bucket",
        "exists": False,
        "objects_listable": False,
        "objects_readable": False,
        "objects_writable": False,
    }])
    result = _parse_s3scanner_output(data)
    assert result[0]["exists"] is False
    assert result[0]["writable"] is False


def test_parse_s3scanner_accepts_bucket_field_alias():
    """s3scanner v1 used 'bucket' instead of 'name'."""
    data = json.dumps([{"bucket": "legacy-bucket", "exists": True}])
    result = _parse_s3scanner_output(data)
    assert result[0]["bucket"] == "legacy-bucket"


def test_parse_s3scanner_multiple_entries():
    data = json.dumps([
        {"name": "bucket-a", "exists": True, "objects_writable": True},
        {"name": "bucket-b", "exists": True, "objects_writable": False},
    ])
    result = _parse_s3scanner_output(data)
    assert len(result) == 2


def test_parse_s3scanner_v2_name_takes_priority_over_bucket():
    data = json.dumps([{"name": "primary", "bucket": "fallback", "exists": True}])
    result = _parse_s3scanner_output(data)
    assert result[0]["bucket"] == "primary"


def test_parse_s3scanner_empty_name_falls_back_to_bucket():
    data = json.dumps([{"name": "", "bucket": "fallback", "exists": True}])
    result = _parse_s3scanner_output(data)
    assert result[0]["bucket"] == "fallback"


# ── _classify_s3scanner_result ────────────────────────────────────────────────

def test_classify_s3_writable_is_critical():
    entry = {"bucket": "test", "exists": True, "listable": True, "readable": True, "writable": True}
    result = _classify_s3scanner_result(entry)
    assert result is not None
    assert "vulnerability" in result
    assert result["vulnerability"]["severity"] == "critical"


def test_classify_s3_listable_only_is_high():
    entry = {"bucket": "test", "exists": True, "listable": True, "readable": True, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_s3_readable_only_is_medium():
    entry = {"bucket": "test", "exists": True, "listable": False, "readable": True, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert result["vulnerability"]["severity"] == "medium"


def test_classify_s3_restricted_is_observation():
    entry = {"bucket": "test", "exists": True, "listable": False, "readable": False, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert result is not None
    assert "observation" in result


def test_classify_s3_not_exists_is_observation():
    entry = {"bucket": "ghost", "exists": False, "listable": False, "readable": False, "writable": False}
    result = _classify_s3scanner_result(entry)
    assert "observation" in result
    assert "not_found" in result["observation"]["value"]


def test_classify_s3_always_sets_section_id():
    entry = {"bucket": "test", "exists": True, "listable": True, "readable": True, "writable": True}
    result = _classify_s3scanner_result(entry)
    assert result["vulnerability"]["section_id"] == _SECTION_ID


# ── _parse_cloud_enum_output ──────────────────────────────────────────────────

def test_parse_cloud_enum_empty_returns_empty_lists():
    result = _parse_cloud_enum_output("")
    assert result == {"s3": [], "azure": [], "gcs": []}


def test_parse_cloud_enum_aws_line():
    text = "[+] AWS: https://exampleco.s3.amazonaws.com"
    result = _parse_cloud_enum_output(text)
    assert len(result["s3"]) == 1
    assert result["s3"][0] == "https://exampleco.s3.amazonaws.com"


def test_parse_cloud_enum_azure_line():
    text = "[+] Azure: https://exampleco.blob.core.windows.net"
    result = _parse_cloud_enum_output(text)
    assert len(result["azure"]) == 1
    assert result["azure"][0] == "https://exampleco.blob.core.windows.net"


def test_parse_cloud_enum_gcp_line():
    text = "[+] GCP: https://storage.googleapis.com/exampleco"
    result = _parse_cloud_enum_output(text)
    assert len(result["gcs"]) == 1
    assert result["gcs"][0] == "https://storage.googleapis.com/exampleco"


def test_parse_cloud_enum_unknown_lines_skipped():
    text = "Scanning...\n[+] AWS: https://exampleco.s3.amazonaws.com\nDone."
    result = _parse_cloud_enum_output(text)
    assert len(result["s3"]) == 1
    assert result["azure"] == []
    assert result["gcs"] == []


def test_parse_cloud_enum_multiple_providers():
    text = (
        "[+] AWS: https://exampleco.s3.amazonaws.com\n"
        "[+] Azure: https://exampleco.blob.core.windows.net\n"
        "[+] GCP: https://storage.googleapis.com/exampleco\n"
    )
    result = _parse_cloud_enum_output(text)
    assert len(result["s3"]) == 1
    assert len(result["azure"]) == 1
    assert len(result["gcs"]) == 1


# ── _parse_azcopy_output ──────────────────────────────────────────────────────

def test_parse_azcopy_accessible_when_info_lines_present():
    text = (
        "INFO: https://account.blob.core.windows.net/container/file.txt; "
        "Content Length: 100"
    )
    result = _parse_azcopy_output(text)
    assert len(result) == 1
    assert result[0]["accessible"] is True


def test_parse_azcopy_not_accessible_on_403():
    text = "RESPONSE Status: 403 Server failed to authenticate the request."
    result = _parse_azcopy_output(text)
    assert result[0]["accessible"] is False


def test_parse_azcopy_not_accessible_on_404():
    text = "RESPONSE Status: 404 The specified resource does not exist."
    result = _parse_azcopy_output(text)
    assert result[0]["accessible"] is False


def test_parse_azcopy_not_accessible_on_empty():
    result = _parse_azcopy_output("")
    assert result[0]["accessible"] is False


def test_parse_azcopy_not_accessible_on_auth_failure():
    text = "AuthorizationFailure: Server failed to authenticate."
    result = _parse_azcopy_output(text)
    assert result[0]["accessible"] is False


def test_parse_azcopy_not_accessible_on_5xx():
    text = "RESPONSE Status: 500 Internal Server Error"
    result = _parse_azcopy_output(text)
    assert result[0]["accessible"] is False


# ── _classify_azure_probe ─────────────────────────────────────────────────────


def test_classify_azure_write_success_is_critical():
    result = _classify_azure_probe(_AZURE_URL, True, True, 201)
    assert result is not None
    assert result["vulnerability"]["severity"] == "critical"
    assert result["vulnerability"]["section_id"] == _SECTION_ID


def test_classify_azure_list_only_is_high():
    result = _classify_azure_probe(_AZURE_URL, True, False, 403)
    assert result["vulnerability"]["severity"] == "high"


def test_classify_azure_read_only_is_medium():
    result = _classify_azure_probe(_AZURE_URL, False, True, 403)
    assert result["vulnerability"]["severity"] == "medium"


def test_classify_azure_fully_restricted_returns_none():
    result = _classify_azure_probe(_AZURE_URL, False, False, 403)
    assert result is None


def test_classify_azure_write_without_list_is_critical():
    result = _classify_azure_probe(_AZURE_URL, False, False, 201)
    assert result["vulnerability"]["severity"] == "critical"
