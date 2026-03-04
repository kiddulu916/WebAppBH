import json
from unittest.mock import MagicMock

from workers.recon_core.concurrency import WeightClass


def test_subfinder_is_light():
    from workers.recon_core.tools.subfinder import Subfinder
    assert Subfinder.weight_class == WeightClass.LIGHT


def test_subfinder_build_command():
    from workers.recon_core.tools.subfinder import Subfinder
    tool = Subfinder()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "subfinder" in cmd[0]
    assert "-d" in cmd
    assert "example.com" in cmd


def test_subfinder_parse_output_json():
    from workers.recon_core.tools.subfinder import Subfinder
    tool = Subfinder()
    output = '{"host":"a.example.com"}\n{"host":"b.example.com"}\n'
    results = tool.parse_output(output)
    assert results == ["a.example.com", "b.example.com"]


def test_subfinder_parse_output_plain():
    from workers.recon_core.tools.subfinder import Subfinder
    tool = Subfinder()
    output = "a.example.com\nb.example.com\n"
    results = tool.parse_output(output)
    assert results == ["a.example.com", "b.example.com"]


def test_assetfinder_is_light():
    from workers.recon_core.tools.assetfinder import Assetfinder
    assert Assetfinder.weight_class == WeightClass.LIGHT


def test_assetfinder_build_command():
    from workers.recon_core.tools.assetfinder import Assetfinder
    tool = Assetfinder()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "assetfinder" in cmd[0]
    assert "example.com" in cmd


def test_chaos_is_light():
    from workers.recon_core.tools.chaos import Chaos
    assert Chaos.weight_class == WeightClass.LIGHT


def test_amass_passive_is_heavy():
    from workers.recon_core.tools.amass import AmassPassive
    assert AmassPassive.weight_class == WeightClass.HEAVY


def test_amass_passive_build_command():
    from workers.recon_core.tools.amass import AmassPassive
    tool = AmassPassive()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "amass" in cmd[0]
    assert "enum" in cmd
    assert "-passive" in cmd


def test_amass_active_is_heavy():
    from workers.recon_core.tools.amass import AmassActive
    assert AmassActive.weight_class == WeightClass.HEAVY
