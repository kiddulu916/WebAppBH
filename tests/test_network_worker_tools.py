"""Tests for network_worker tools."""

import os

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_network_worker_concurrency_weight_classes():
    from workers.network_worker.concurrency import WeightClass

    assert WeightClass.LIGHT.value == "light"
    assert WeightClass.MEDIUM.value == "medium"
    assert WeightClass.HEAVY.value == "heavy"


def test_network_worker_concurrency_get_semaphore():
    from workers.network_worker.concurrency import WeightClass, get_semaphore

    for wc in WeightClass:
        sem = get_semaphore(wc)
        assert sem is not None


def test_network_test_tool_is_abstract():
    import inspect
    from workers.network_worker.base_tool import NetworkTestTool

    assert inspect.isabstract(NetworkTestTool)


def test_network_test_tool_has_required_helpers():
    from workers.network_worker.base_tool import NetworkTestTool

    assert hasattr(NetworkTestTool, "run_subprocess")
    assert hasattr(NetworkTestTool, "check_cooldown")
    assert hasattr(NetworkTestTool, "update_tool_state")
    assert hasattr(NetworkTestTool, "_save_location")
    assert hasattr(NetworkTestTool, "_save_observation_tech_stack")
    assert hasattr(NetworkTestTool, "_save_vulnerability")
    assert hasattr(NetworkTestTool, "_load_oos_attacks")
    assert hasattr(NetworkTestTool, "_get_non_http_locations")


def test_load_oos_attacks_missing_file(tmp_path):
    from workers.network_worker.base_tool import NetworkTestTool

    class DummyTool(NetworkTestTool):
        name = "dummy"
        weight_class = None
        async def execute(self, *a, **kw):
            return {}

    tool = DummyTool()
    result = tool._load_oos_attacks_sync(str(tmp_path / "nonexistent"))
    assert result == []


def test_load_oos_attacks_reads_profile(tmp_path):
    import json
    from workers.network_worker.base_tool import NetworkTestTool

    class DummyTool(NetworkTestTool):
        name = "dummy"
        weight_class = None
        async def execute(self, *a, **kw):
            return {}

    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"oos_attacks": ["dos", "exploit/multi/handler"]}))

    tool = DummyTool()
    result = tool._load_oos_attacks_sync(str(profile))
    assert result == ["dos", "exploit/multi/handler"]


def test_default_creds_yaml_loads():
    import yaml
    from pathlib import Path

    creds_path = Path(__file__).resolve().parent.parent / "workers" / "network_worker" / "wordlists" / "default_creds.yaml"
    with open(creds_path) as f:
        creds = yaml.safe_load(f)

    assert isinstance(creds, dict)
    assert "ssh" in creds
    assert "mysql" in creds
    assert "ftp" in creds
    for service, pairs in creds.items():
        assert isinstance(pairs, list)
        for pair in pairs:
            assert len(pair) == 2


def test_cve_to_msf_yaml_loads():
    import yaml
    from pathlib import Path

    map_path = Path(__file__).resolve().parent.parent / "workers" / "network_worker" / "mappings" / "cve_to_msf.yaml"
    with open(map_path) as f:
        mappings = yaml.safe_load(f)

    assert isinstance(mappings, dict)
    assert "CVE-2017-0144" in mappings
    for cve_id, info in mappings.items():
        assert "module" in info
        assert "service" in info
        assert "ports" in info
        assert isinstance(info["ports"], list)
