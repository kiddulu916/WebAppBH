"""Docker-secrets-aware configuration reader.

Usage::

    from lib_webbh.secrets import get_secret

    db_pass = get_secret("DB_PASS", default="changeme")

Resolution order:
1. ``{NAME}_FILE`` env var → read contents of that file (Docker secret mount)
2. ``{NAME}`` env var → use value directly
3. *default* fallback
"""
from __future__ import annotations

import os
from pathlib import Path


def get_secret(name: str, default: str = "") -> str:
    """Return the value of a secret by *name*, preferring file-based secrets."""
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        p = Path(file_path)
        if p.is_file():
            return p.read_text().strip()
    return os.environ.get(name, default)
