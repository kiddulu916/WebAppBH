"""Wildcard pattern matching engine for domains, IPs, and URL paths.

Supports:
- Domain wildcards: *.example.com, **.example.com
- IP wildcards: 10.*.0.*, CIDR notation (10.0.0.0/8)
- Path wildcards: example.com/api/*, example.com/**/secret, **/api/v1/*
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network


def match_domain(value: str, pattern: str) -> bool:
    """Match a domain against a wildcard pattern.

    * and ** at the start match any subdomain(s). The base domain must match.
    """
    value = value.lower()
    pattern = pattern.lower()

    if value == pattern:
        return True

    # *.example.com or **.example.com — match any subdomain of the base
    if pattern.startswith("*.") or pattern.startswith("**."):
        base = pattern.lstrip("*").lstrip(".")
        return value.endswith("." + base)

    return False


def match_ip(value: str, pattern: str) -> bool:
    """Match an IP address against an exact IP, CIDR range, or octet wildcard."""
    # CIDR notation
    if "/" in pattern:
        try:
            return IPv4Address(value) in IPv4Network(pattern, strict=False)
        except ValueError:
            return False

    # Octet wildcard (e.g. 10.*.0.*)
    if "*" in pattern:
        val_octets = value.split(".")
        pat_octets = pattern.split(".")
        if len(val_octets) != 4 or len(pat_octets) != 4:
            return False
        return all(
            p == "*" or p == v
            for v, p in zip(val_octets, pat_octets)
        )

    # Exact match
    return value == pattern


def match_path(value: str, pattern: str) -> bool:
    """Match a URL path against a glob-style pattern.

    Supports:
    - * matches a single path segment or filename component
    - ** (globstar) matches zero or more path segments
    """
    value = value.lower()
    pattern = pattern.lower()

    if value == pattern:
        return True

    # Convert glob pattern to regex
    regex = _path_pattern_to_regex(pattern)
    return bool(re.match(regex, value))


def _path_pattern_to_regex(pattern: str) -> str:
    """Convert a path glob pattern to a regex string."""
    parts = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                # ** — match zero or more path segments
                parts.append(".*")
                i += 2
                # Skip trailing / after **
                if i < len(pattern) and pattern[i] == "/":
                    parts.append("/?")
                    i += 1
            else:
                # * — match anything within a single segment (no /)
                parts.append("[^/]*")
                i += 1
        elif c == ".":
            parts.append(r"\.")
            i += 1
        elif c == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(c))
            i += 1
    return "^" + "".join(parts) + "$"


_IP_PATTERN = re.compile(
    r"^[\d*]+\.[\d*]+\.[\d*]+\.[\d*]+(/\d+)?$"
)


def match_pattern(value: str, pattern: str) -> bool:
    """Auto-detect pattern type and dispatch to the appropriate matcher.

    Detection order:
    1. If pattern contains '/' with path segments → path match
    2. If pattern looks like IP/CIDR (digits, dots, wildcards, slash) → IP match
    3. Otherwise → domain match
    """
    # Path patterns: contain / after a domain-like prefix or start with **
    if "/" in pattern:
        # Could be CIDR (10.0.0.0/8) or path (example.com/api/*)
        if _IP_PATTERN.match(pattern):
            return match_ip(value, pattern)
        return match_path(value, pattern)

    # IP patterns: digits, dots, and wildcards only
    if _IP_PATTERN.match(pattern):
        return match_ip(value, pattern)

    # Default: domain pattern
    return match_domain(value, pattern)
