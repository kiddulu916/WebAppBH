# tests/test_chain_worker_findings_collector.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import json
import pytest
from workers.chain_worker.tools.findings_collector import FindingsCollector, _load_test_accounts
from workers.chain_worker.concurrency import WeightClass


def test_tool_attributes():
    tool = FindingsCollector()
    assert tool.name == "findings_collector"
    assert tool.weight_class == WeightClass.LIGHT


def test_load_test_accounts_from_profile(tmp_path):
    profile = {
        "in_scope_domains": ["example.com"],
        "test_accounts": {
            "attacker": {"username": "atk@test.com", "password": "pass1"},
            "victim": {"username": "vic@test.com", "password": "pass2"},
        },
    }
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile))
    accounts = _load_test_accounts(str(profile_path))
    assert accounts is not None
    assert accounts.attacker.username == "atk@test.com"
    assert accounts.victim.password == "pass2"


def test_load_test_accounts_missing_key(tmp_path):
    profile = {"in_scope_domains": ["example.com"]}
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile))
    accounts = _load_test_accounts(str(profile_path))
    assert accounts is None


def test_load_test_accounts_missing_file():
    accounts = _load_test_accounts("/nonexistent/profile.json")
    assert accounts is None
