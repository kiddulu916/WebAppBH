import json
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_naabu_is_heavy():
    from workers.recon_core.tools.naabu import Naabu
    assert Naabu.weight_class == WeightClass.HEAVY


def test_naabu_build_command():
    from workers.recon_core.tools.naabu import Naabu
    tool = Naabu()
    tool._input_file = "/tmp/ips.txt"
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "naabu" in cmd[0]
    assert "-list" in cmd
    assert "/tmp/ips.txt" in cmd
    assert "-json" in cmd


def test_naabu_parse_output():
    from workers.recon_core.tools.naabu import Naabu
    tool = Naabu()
    line1 = json.dumps({"ip": "1.2.3.4", "port": 80})
    line2 = json.dumps({"ip": "1.2.3.4", "port": 443})
    line3 = json.dumps({"ip": "5.6.7.8", "port": 22})
    output = f"{line1}\n{line2}\n{line3}\n"
    results = tool.parse_output(output)
    assert len(results) == 3
    assert results[0] == {"ip": "1.2.3.4", "port": 80}
    assert results[2] == {"ip": "5.6.7.8", "port": 22}
