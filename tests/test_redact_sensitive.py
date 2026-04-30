"""Tests for lib_webbh.logger.redact_sensitive."""
from __future__ import annotations

from lib_webbh.logger import redact_sensitive


def test_returns_none_for_none() -> None:
    assert redact_sensitive(None) is None


def test_passes_through_clean_text() -> None:
    assert redact_sensitive("Hello, world") == "Hello, world"


def test_redacts_bearer_token_in_authorization_header() -> None:
    s = "Authorization: Bearer abcdef.ghijkl.mnopqr"
    out = redact_sensitive(s) or ""
    assert "abcdef.ghijkl.mnopqr" not in out
    assert "[REDACTED]" in out


def test_redacts_api_key_query_param() -> None:
    s = "https://example.com/?api_key=supersecret123&other=val"
    out = redact_sensitive(s) or ""
    assert "supersecret123" not in out
    assert "[REDACTED]" in out


def test_redacts_x_api_key_header() -> None:
    s = "X-API-KEY: bN9zXqL2pQ7mR5kT"
    out = redact_sensitive(s) or ""
    assert "bN9zXqL2pQ7mR5kT" not in out


def test_redacts_password_assignment() -> None:
    s = "DB connection failed for user=admin password=hunter2"
    out = redact_sensitive(s) or ""
    assert "hunter2" not in out


def test_redacts_jwt_token() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abcdef123456"
    s = f"Got token {jwt} in response"
    out = redact_sensitive(s) or ""
    assert jwt not in out


def test_redacts_session_cookie() -> None:
    s = "Set-Cookie: PHPSESSID=abcdef0123456789; Path=/"
    out = redact_sensitive(s) or ""
    assert "abcdef0123456789" not in out


def test_truncates_long_strings() -> None:
    long = "a" * 5000
    out = redact_sensitive(long, max_len=1000) or ""
    assert len(out) < 1100
    assert out.endswith("...[truncated]")
