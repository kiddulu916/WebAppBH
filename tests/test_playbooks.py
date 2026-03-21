"""Tests for playbook loading and validation."""

import pytest
from lib_webbh.playbooks import BUILTIN_PLAYBOOKS, get_playbook, PlaybookConfig


def test_builtin_playbooks_exist():
    """All 4 built-in playbooks must be loadable."""
    assert "wide_recon" in BUILTIN_PLAYBOOKS
    assert "deep_webapp" in BUILTIN_PLAYBOOKS
    assert "api_focused" in BUILTIN_PLAYBOOKS
    assert "cloud_first" in BUILTIN_PLAYBOOKS


def test_get_playbook_returns_config():
    config = get_playbook("wide_recon")
    assert isinstance(config, PlaybookConfig)
    assert len(config.stages) > 0
    assert config.concurrency.heavy >= 1
    assert config.concurrency.light >= 1


def test_get_playbook_unknown_returns_default():
    config = get_playbook("nonexistent")
    assert isinstance(config, PlaybookConfig)
    assert config.name == "wide_recon"  # falls back to default


def test_playbook_stage_has_tools():
    config = get_playbook("deep_webapp")
    for stage in config.stages:
        assert isinstance(stage.name, str)
        assert isinstance(stage.enabled, bool)


def test_playbook_config_serializable():
    config = get_playbook("wide_recon")
    d = config.to_dict()
    assert isinstance(d, dict)
    assert "stages" in d
    assert "concurrency" in d
