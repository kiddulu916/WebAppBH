import json
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_massdns_is_light():
    from workers.recon_core.tools.massdns import Massdns
    assert Massdns.weight_class == WeightClass.LIGHT


def test_httpx_is_light():
    from workers.recon_core.tools.httpx_tool import HttpxTool
    assert HttpxTool.weight_class == WeightClass.LIGHT


def test_httpx_build_command_includes_headers():
    from workers.recon_core.tools.httpx_tool import HttpxTool
    tool = HttpxTool()
    tool._input_file = "/tmp/test.txt"
    target = MagicMock(base_domain="example.com")
    headers = {"Authorization": "Bearer token123"}
    cmd = tool.build_command(target, headers=headers)
    assert "-H" in cmd
    idx = cmd.index("-H")
    assert "Authorization: Bearer token123" in cmd[idx + 1]


def test_httpx_parse_output():
    from workers.recon_core.tools.httpx_tool import HttpxTool
    tool = HttpxTool()
    line1 = json.dumps({
        "url": "https://a.example.com",
        "status_code": 200,
        "title": "Home",
        "tech": ["nginx"],
    })
    line2 = json.dumps({
        "url": "https://b.example.com",
        "status_code": 403,
        "title": "Forbidden",
        "tech": [],
    })
    output = f"{line1}\n{line2}\n"
    results = tool.parse_output(output)
    assert len(results) == 2
    assert results[0]["url"] == "https://a.example.com"
    assert results[0]["status_code"] == 200
