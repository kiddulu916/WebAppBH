import json
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_subjack_is_light():
    from workers.recon_core.tools.subjack import SubjackTool
    assert SubjackTool.weight_class == WeightClass.LIGHT


def test_subjack_build_command():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    tool._input_file = "/tmp/domains.txt"
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert cmd[0] == "subjack"
    assert "-w" in cmd
    assert "/tmp/domains.txt" in cmd
    assert "-ssl" in cmd
    assert "-a" in cmd
    assert "/opt/fingerprints.json" in cmd


def test_subjack_parse_output_vulnerable():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    line1 = json.dumps({
        "subdomain": "blog.example.com",
        "vulnerable": True,
        "service": "github",
        "fingerprint": "There isn't a GitHub Pages site here.",
    })
    line2 = json.dumps({
        "subdomain": "shop.example.com",
        "vulnerable": True,
        "service": "shopify",
        "fingerprint": "Sorry, this shop is currently unavailable.",
    })
    output = f"{line1}\n{line2}\n"
    results = tool.parse_output(output)
    assert len(results) == 2
    assert results[0]["subdomain"] == "blog.example.com"
    assert results[0]["service"] == "github"
    assert results[0]["fingerprint"] == "There isn't a GitHub Pages site here."
    assert results[1]["subdomain"] == "shop.example.com"
    assert results[1]["service"] == "shopify"


def test_subjack_parse_output_not_vulnerable():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    line1 = json.dumps({
        "subdomain": "www.example.com",
        "vulnerable": False,
        "service": "",
        "fingerprint": "",
    })
    output = f"{line1}\n"
    results = tool.parse_output(output)
    assert len(results) == 0


def test_subjack_parse_output_empty():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    assert tool.parse_output("") == []
    assert tool.parse_output("  \n  \n") == []


def test_subjack_parse_output_malformed():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    output = "not json\n{broken\n"
    results = tool.parse_output(output)
    assert results == []
