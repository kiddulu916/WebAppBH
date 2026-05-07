"""Test that worker _filter_stages handles new playbook format."""
from lib_webbh.playbooks import get_playbook, get_worker_stages


def test_filter_stages_new_format():
    """Verify get_worker_stages extracts correctly from new format."""
    pb = get_playbook("deep_webapp").to_dict()
    # info_gathering should have stages, with 2 disabled
    stages = get_worker_stages(pb, "info_gathering")
    assert stages is not None
    disabled = [s for s in stages if not s["enabled"]]
    assert len(disabled) == 2

    # mobile_worker should be empty (disabled worker)
    mobile = get_worker_stages(pb, "mobile_worker")
    assert mobile == []


def test_filter_stages_none_playbook():
    """None playbook means run all stages."""
    assert get_worker_stages(None, "info_gathering") is None
