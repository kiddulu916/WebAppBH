"""Tests for the hierarchical playbook model."""
import pytest
from lib_webbh.playbooks import (
    BUILTIN_PLAYBOOKS, PIPELINE_STAGES, PlaybookConfig, WorkerConfig,
    StageConfig, ConcurrencyConfig, build_worker_config, get_worker_stages,
    get_playbook,
)


def test_pipeline_stages_registry_has_all_workers():
    expected = [
        "info_gathering", "config_mgmt", "identity_mgmt", "authentication",
        "authorization", "session_mgmt", "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side", "mobile_worker",
        "reasoning_worker", "chain_worker", "reporting",
    ]
    for w in expected:
        assert w in PIPELINE_STAGES, f"Missing worker: {w}"
        assert len(PIPELINE_STAGES[w]) > 0, f"Empty stages for: {w}"


def test_build_worker_config_all_enabled():
    wc = build_worker_config("info_gathering")
    assert wc.name == "info_gathering"
    assert wc.enabled is True
    assert len(wc.stages) == 10
    assert all(s.enabled for s in wc.stages)


def test_build_worker_config_disabled():
    wc = build_worker_config("mobile_worker", enabled=False)
    assert wc.enabled is False


def test_build_worker_config_with_disabled_stages():
    wc = build_worker_config(
        "info_gathering",
        disabled_stages=["search_engine_recon", "enumerate_subdomains"],
    )
    disabled = [s for s in wc.stages if not s.enabled]
    assert len(disabled) == 2
    assert {s.name for s in disabled} == {"search_engine_recon", "enumerate_subdomains"}


def test_build_worker_config_custom_concurrency():
    wc = build_worker_config("input_validation", concurrency=ConcurrencyConfig(heavy=3, light=6))
    assert wc.concurrency.heavy == 3
    assert wc.concurrency.light == 6


def test_playbook_config_has_workers():
    config = get_playbook("wide_recon")
    assert isinstance(config, PlaybookConfig)
    assert hasattr(config, "workers")
    assert len(config.workers) == 15


def test_playbook_config_serializable():
    config = get_playbook("wide_recon")
    d = config.to_dict()
    assert "workers" in d
    assert isinstance(d["workers"], list)
    assert all("stages" in w for w in d["workers"])


def test_wide_recon_all_enabled():
    config = get_playbook("wide_recon")
    for w in config.workers:
        assert w.enabled is True
        assert all(s.enabled for s in w.stages)


def test_deep_webapp_mobile_disabled():
    config = get_playbook("deep_webapp")
    mobile = next(w for w in config.workers if w.name == "mobile_worker")
    assert mobile.enabled is False


def test_api_focused_disables_client_side_session_mobile():
    config = get_playbook("api_focused")
    disabled = {w.name for w in config.workers if not w.enabled}
    assert "client_side" in disabled
    assert "mobile_worker" in disabled
    assert "session_mgmt" in disabled


def test_api_focused_info_gathering_partial():
    config = get_playbook("api_focused")
    ig = next(w for w in config.workers if w.name == "info_gathering")
    enabled_names = {s.name for s in ig.stages if s.enabled}
    assert "web_server_fingerprint" in enabled_names
    assert "identify_entry_points" in enabled_names
    assert "search_engine_recon" not in enabled_names


def test_get_worker_stages_extracts_correctly():
    config = get_playbook("wide_recon")
    d = config.to_dict()
    stages = get_worker_stages(d, "info_gathering")
    assert stages is not None
    assert len(stages) == 10


def test_get_worker_stages_disabled_worker():
    config = get_playbook("deep_webapp")
    d = config.to_dict()
    stages = get_worker_stages(d, "mobile_worker")
    assert stages == []


def test_get_worker_stages_missing_playbook():
    stages = get_worker_stages(None, "info_gathering")
    assert stages is None


def test_get_playbook_unknown_returns_default():
    config = get_playbook("nonexistent")
    assert config.name == "wide_recon"


def test_all_four_builtins_exist():
    assert "wide_recon" in BUILTIN_PLAYBOOKS
    assert "deep_webapp" in BUILTIN_PLAYBOOKS
    assert "api_focused" in BUILTIN_PLAYBOOKS
    assert "cloud_first" in BUILTIN_PLAYBOOKS
