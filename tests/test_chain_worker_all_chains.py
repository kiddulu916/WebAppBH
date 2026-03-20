# tests/test_chain_worker_all_chains.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.registry import get_registry, get_chains_by_category
import workers.chain_worker.chains  # noqa: F401


def test_total_chain_count():
    registry = get_registry()
    assert len(registry) == 180, f"Expected 180, got {len(registry)}"


def test_category_counts():
    expected = {
        "auth_session": 22,
        "injection_execution": 22,
        "ssrf_infrastructure": 20,
        "xss_client_side": 19,
        "file_processing": 19,
        "header_protocol": 20,
        "access_control": 21,
        "bypass": 19,
        "platform_protocol": 18,
    }
    for category, count in expected.items():
        chains = get_chains_by_category(category)
        assert len(chains) == count, f"'{category}': expected {count}, got {len(chains)}"


def test_all_unique_names():
    registry = get_registry()
    names = list(registry.keys())
    assert len(names) == len(set(names))


def test_all_have_required_attributes():
    registry = get_registry()
    for name, chain in registry.items():
        assert chain.name, f"{name} missing name"
        assert chain.category, f"{name} missing category"
        assert chain.severity_on_success in ("critical", "high"), f"{name} bad severity"
