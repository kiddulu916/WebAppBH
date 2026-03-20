import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import json
import pytest
from unittest.mock import AsyncMock, patch


async def _create_tables():
    from lib_webbh.database import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


# ---------------------------------------------------------------------------
# SecretScanner tests
# ---------------------------------------------------------------------------


def test_secret_scanner_regex_aws_key():
    from workers.mobile_worker.tools.secret_scanner import SecretScannerTool
    tool = SecretScannerTool()
    findings = tool._scan_text('String key = "AKIAIOSFODNN7EXAMPLE";')
    types = [f["type"] for f in findings]
    assert "aws_key" in types


def test_secret_scanner_regex_firebase():
    from workers.mobile_worker.tools.secret_scanner import SecretScannerTool
    tool = SecretScannerTool()
    findings = tool._scan_text('url = "https://myapp-123.firebaseio.com/data"')
    types = [f["type"] for f in findings]
    assert "firebase_url" in types


def test_secret_scanner_regex_google_api_key():
    from workers.mobile_worker.tools.secret_scanner import SecretScannerTool
    tool = SecretScannerTool()
    findings = tool._scan_text('api_key = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"')
    types = [f["type"] for f in findings]
    assert "google_api_key" in types


def test_secret_scanner_regex_private_key():
    from workers.mobile_worker.tools.secret_scanner import SecretScannerTool
    tool = SecretScannerTool()
    findings = tool._scan_text('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...')
    types = [f["type"] for f in findings]
    assert "private_key" in types


def test_secret_scanner_regex_password():
    from workers.mobile_worker.tools.secret_scanner import SecretScannerTool
    tool = SecretScannerTool()
    findings = tool._scan_text('password = "SuperSecret123!"')
    types = [f["type"] for f in findings]
    assert "hardcoded_password" in types


def test_secret_scanner_severity_mapping():
    from workers.mobile_worker.tools.secret_scanner import SecretScannerTool
    tool = SecretScannerTool()
    assert tool._severity_for("aws_key") == "critical"
    assert tool._severity_for("private_key") == "critical"
    assert tool._severity_for("firebase_url") == "high"
    assert tool._severity_for("google_api_key") == "high"
    assert tool._severity_for("hardcoded_password") == "high"


# ---------------------------------------------------------------------------
# MobsfSecrets tests
# ---------------------------------------------------------------------------


def test_mobsf_secrets_deduplication():
    from workers.mobile_worker.tools.mobsf_secrets import MobsfSecretsTool
    tool = MobsfSecretsTool()
    mobsf_findings = [
        {"title": "Hardcoded Secret", "description": "AKIAIOSFODNN7EXAMPLE found"},
        {"title": "API Key Exposed", "description": "Some other secret"},
    ]
    existing_values = {"AKIAIOSFODNN7EXAMPLE"}
    deduped = tool._deduplicate(mobsf_findings, existing_values)
    # First one should be filtered (secret value in existing)
    assert len(deduped) == 1
    assert "Some other secret" in deduped[0]["description"]


def test_mobsf_secrets_parses_report():
    from workers.mobile_worker.tools.mobsf_secrets import MobsfSecretsTool
    tool = MobsfSecretsTool()
    report = {
        "secrets": [
            {"title": "AWS Key", "description": "AKIAIOSFODNN7EXAMPLE", "severity": "high"},
            {"title": "Firebase URL", "description": "https://app.firebaseio.com", "severity": "warning"},
        ]
    }
    findings = tool._extract_secrets(report)
    assert len(findings) == 2
