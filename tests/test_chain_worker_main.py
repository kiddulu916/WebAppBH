# tests/test_chain_worker_main.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest


def test_get_container_name_default(monkeypatch):
    monkeypatch.delenv("HOSTNAME", raising=False)
    from workers.chain_worker.main import get_container_name
    assert get_container_name() == "chain-worker-unknown"


def test_get_container_name_from_env(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "webbh-chain-worker-1")
    from workers.chain_worker.main import get_container_name
    assert get_container_name() == "webbh-chain-worker-1"
