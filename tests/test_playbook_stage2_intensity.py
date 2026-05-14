from lib_webbh.playbooks import get_worker_stages


def test_default_intensity_low_when_omitted():
    pb = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True},
    ]}]}
    stages = get_worker_stages(pb, "info_gathering")
    s = next(s for s in stages if s["name"] == "web_server_fingerprint")
    assert s.get("config", {}).get("fingerprint_intensity", "low") == "low"


def test_explicit_intensity_passes_through():
    pb = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True,
         "config": {"fingerprint_intensity": "high"}},
    ]}]}
    stages = get_worker_stages(pb, "info_gathering")
    s = next(s for s in stages if s["name"] == "web_server_fingerprint")
    assert s["config"]["fingerprint_intensity"] == "high"
