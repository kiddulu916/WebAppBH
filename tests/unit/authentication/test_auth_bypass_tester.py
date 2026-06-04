"""Unit tests for AuthBypassTester sync helpers (WSTG-ATHN-04)."""
from types import SimpleNamespace
import pytest

from workers.authentication.tools.auth_bypass_tester import AuthBypassTester


def _resp(status_code: int, text: str = "", location: str = "", headers: dict | None = None) -> SimpleNamespace:
    """Build a minimal response object for testing helpers."""
    h = dict(headers or {})
    if location:
        h["location"] = location
    return SimpleNamespace(status_code=status_code, text=text, headers=h)


# ---------------------------------------------------------------------------
# _is_protected
# ---------------------------------------------------------------------------

def test_is_protected_none_returns_true():
    assert AuthBypassTester()._is_protected(None) is True

def test_is_protected_401_returns_true():
    assert AuthBypassTester()._is_protected(_resp(401)) is True

def test_is_protected_403_returns_true():
    assert AuthBypassTester()._is_protected(_resp(403)) is True

def test_is_protected_redirect_to_login_returns_true():
    assert AuthBypassTester()._is_protected(_resp(302, location="/login")) is True

def test_is_protected_redirect_to_signin_returns_true():
    assert AuthBypassTester()._is_protected(_resp(302, location="/signin")) is True

def test_is_protected_body_login_required_returns_true():
    assert AuthBypassTester()._is_protected(_resp(200, text="login required")) is True

def test_is_protected_body_access_denied_returns_true():
    assert AuthBypassTester()._is_protected(_resp(200, text="access denied")) is True

def test_is_protected_200_normal_content_returns_false():
    assert AuthBypassTester()._is_protected(_resp(200, text="Welcome to the dashboard")) is False

def test_is_protected_302_to_home_returns_false():
    assert AuthBypassTester()._is_protected(_resp(302, location="/home")) is False


# ---------------------------------------------------------------------------
# _is_rate_limited
# ---------------------------------------------------------------------------

def test_is_rate_limited_none_returns_false():
    assert AuthBypassTester()._is_rate_limited(None) is False

def test_is_rate_limited_429_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(429)) is True

def test_is_rate_limited_body_too_many_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="too many requests")) is True

def test_is_rate_limited_body_blocked_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="your ip is blocked")) is True

def test_is_rate_limited_body_rate_limit_returns_true():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="rate limit exceeded")) is True

def test_is_rate_limited_200_normal_returns_false():
    assert AuthBypassTester()._is_rate_limited(_resp(200, text="Welcome")) is False
