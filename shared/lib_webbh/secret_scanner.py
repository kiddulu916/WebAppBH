"""Detect leaked secrets in tool output."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SecretMatch:
    pattern_name: str
    matched_value: str
    line_number: int


PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}'),
    "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),
    "generic_api_key": re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*["\']?[A-Za-z0-9]{20,}'),
    "jwt_token": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "private_key": re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "stripe_key": re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
    "heroku_api_key": re.compile(r'(?i)heroku.*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
}


def scan_text(text: str) -> list[SecretMatch]:
    """Scan text for potential secrets. Returns list of matches with redacted values."""
    matches: list[SecretMatch] = []
    for line_num, line in enumerate(text.split("\n"), 1):
        for name, pattern in PATTERNS.items():
            for m in pattern.finditer(line):
                val = m.group()
                redacted = val[:8] + "..." + val[-4:] if len(val) > 16 else val[:4] + "..."
                matches.append(SecretMatch(
                    pattern_name=name,
                    matched_value=redacted,
                    line_number=line_num,
                ))
    return matches
