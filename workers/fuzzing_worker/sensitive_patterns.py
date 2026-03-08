"""Sensitive file pattern matching for fuzzing results."""
from __future__ import annotations

import re
from typing import TypedDict


class SensitiveMatch(TypedDict):
    category: str
    severity: str
    pattern: str


_PATTERNS: list[tuple[str, str, re.Pattern]] = []


def _p(category: str, severity: str, pattern: str) -> None:
    """Register a sensitive file pattern."""
    _PATTERNS.append((category, severity, re.compile(pattern, re.IGNORECASE)))


# ---------------------------------------------------------------------------
# credentials_keys — critical
# ---------------------------------------------------------------------------
_p("credentials_keys", "critical", r"\.env$")
_p("credentials_keys", "critical", r"\.env\..+")
_p("credentials_keys", "critical", r"\.htpasswd")
_p("credentials_keys", "critical", r"wp-config\.php")
_p("credentials_keys", "critical", r"config\.php")
_p("credentials_keys", "critical", r"settings\.py")
_p("credentials_keys", "critical", r"id_rsa")
_p("credentials_keys", "critical", r"id_dsa")
_p("credentials_keys", "critical", r"id_ecdsa")
_p("credentials_keys", "critical", r"\.pem$")
_p("credentials_keys", "critical", r"\.key$")
_p("credentials_keys", "critical", r"\.pfx$")
_p("credentials_keys", "critical", r"credentials\.json")
_p("credentials_keys", "critical", r"\.aws/credentials")
_p("credentials_keys", "critical", r"\.ssh/")
_p("credentials_keys", "critical", r"\.npmrc$")
_p("credentials_keys", "critical", r"\.pypirc$")

# ---------------------------------------------------------------------------
# database — critical
# ---------------------------------------------------------------------------
_p("database", "critical", r"\.(sql|sqlite|sqlite3|db|dump)$")

# ---------------------------------------------------------------------------
# source_control — high
# ---------------------------------------------------------------------------
_p("source_control", "high", r"\.git/(config|HEAD)")
_p("source_control", "high", r"\.svn/entries")
_p("source_control", "high", r"\.hg/")

# ---------------------------------------------------------------------------
# configuration — high
# ---------------------------------------------------------------------------
_p("configuration", "high", r"web\.config$")
_p("configuration", "high", r"\.htaccess$")
_p("configuration", "high", r"application\.(yml|yaml|properties)$")
_p("configuration", "high", r"composer\.json$")
_p("configuration", "high", r"package\.json$")

# ---------------------------------------------------------------------------
# backup — medium
# ---------------------------------------------------------------------------
_p("backup", "medium", r"\.(bak|old|orig|save|swp|temp|dist|copy)$")
_p("backup", "medium", r"~$")
_p("backup", "medium", r"^\..+\.swp$")  # vim swap files

# ---------------------------------------------------------------------------
# logs_debug — medium
# ---------------------------------------------------------------------------
_p("logs_debug", "medium", r"\.(log|debug)$")
_p("logs_debug", "medium", r"phpinfo\.php")
_p("logs_debug", "medium", r"server-status")
_p("logs_debug", "medium", r"server-info")
_p("logs_debug", "medium", r"elmah\.axd")
_p("logs_debug", "medium", r"trace\.axd")


def check_sensitive(path: str) -> SensitiveMatch | None:
    """Check if a path matches any sensitive file pattern.

    Returns the first matching ``SensitiveMatch`` or ``None``.
    """
    basename = path.rsplit("/", 1)[-1] if "/" in path else path
    for category, severity, pattern in _PATTERNS:
        if pattern.search(path) or pattern.search(basename):
            return SensitiveMatch(
                category=category,
                severity=severity,
                pattern=pattern.pattern,
            )
    return None
