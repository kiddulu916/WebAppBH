"""Remediation advice lookup from static map."""
from __future__ import annotations

from pathlib import Path

import yaml

_MAP_PATH = Path(__file__).parent / "remediation_map.yaml"
_GENERIC = (
    "Review the vulnerability details and assess the affected component. "
    "Apply the principle of least privilege and follow OWASP remediation "
    "guidelines for this class of issue."
)

_cache: list[tuple[list[str], str]] | None = None


def _load_map() -> list[tuple[list[str], str]]:
    global _cache
    if _cache is not None:
        return _cache
    data = yaml.safe_load(_MAP_PATH.read_text())
    _cache = [(entry["keywords"], entry["fix"]) for entry in data.values()]
    return _cache


def lookup_remediation(title: str) -> str:
    """Return remediation advice for a vulnerability title.

    Matches against keyword lists in the YAML map.  Falls back to a
    generic recommendation when no keyword matches.
    """
    title_lower = title.lower()
    for keywords, fix in _load_map():
        if any(kw in title_lower for kw in keywords):
            return fix
    return _GENERIC
