# tests/test_reporting_remediation.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from workers.reporting_worker.remediation import lookup_remediation


def test_lookup_xss():
    result = lookup_remediation("Reflected Cross-Site Scripting (XSS)")
    assert result is not None
    assert "sanitiz" in result.lower() or "encod" in result.lower()


def test_lookup_sqli():
    result = lookup_remediation("SQL Injection in login form")
    assert result is not None
    assert "parameterized" in result.lower() or "prepared" in result.lower()


def test_lookup_ssrf():
    result = lookup_remediation("Server-Side Request Forgery")
    assert result is not None


def test_lookup_unknown_returns_generic():
    result = lookup_remediation("Some Unknown Vulnerability Type ZZZZZ")
    assert result is not None
    assert "review" in result.lower() or "assess" in result.lower()


def test_lookup_case_insensitive():
    r1 = lookup_remediation("xss reflected")
    r2 = lookup_remediation("XSS REFLECTED")
    assert r1 == r2
