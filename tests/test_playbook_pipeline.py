"""Test that the pipeline respects playbook stage.enabled flags."""
import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

from workers.recon_core.pipeline import Pipeline, STAGES


def test_filter_stages_by_playbook():
    pipeline = Pipeline(target_id=1, container_name="test")
    playbook = {
        "stages": [
            {"name": "passive_discovery", "enabled": True},
            {"name": "active_discovery", "enabled": False},
            {"name": "liveness_dns", "enabled": True},
            {"name": "subdomain_takeover", "enabled": False},
            {"name": "fingerprinting", "enabled": True},
            {"name": "port_mapping", "enabled": True},
            {"name": "deep_recon", "enabled": True},
        ]
    }
    filtered = pipeline._filter_stages(playbook)
    names = [s.name for s in filtered]
    assert "active_discovery" not in names
    assert "subdomain_takeover" not in names
    assert "passive_discovery" in names
    assert len(names) == 5


def test_filter_stages_no_playbook():
    pipeline = Pipeline(target_id=1, container_name="test")
    filtered = pipeline._filter_stages(None)
    assert len(filtered) == len(STAGES)


def test_filter_stages_empty_playbook():
    pipeline = Pipeline(target_id=1, container_name="test")
    filtered = pipeline._filter_stages({})
    assert len(filtered) == len(STAGES)
