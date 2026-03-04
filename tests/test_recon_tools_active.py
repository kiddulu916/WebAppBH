from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_sublist3r_is_light():
    from workers.recon_core.tools.sublist3r import Sublist3r
    assert Sublist3r.weight_class == WeightClass.LIGHT


def test_sublist3r_build_command():
    from workers.recon_core.tools.sublist3r import Sublist3r
    tool = Sublist3r()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "example.com" in cmd


def test_sublist3r_parse_output():
    from workers.recon_core.tools.sublist3r import Sublist3r
    tool = Sublist3r()
    output = "a.example.com\nb.example.com\n"
    results = tool.parse_output(output)
    assert results == ["a.example.com", "b.example.com"]


def test_knockpy_is_light():
    from workers.recon_core.tools.knockpy import Knockpy
    assert Knockpy.weight_class == WeightClass.LIGHT


def test_knockpy_build_command():
    from workers.recon_core.tools.knockpy import Knockpy
    tool = Knockpy()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert "knockpy" in cmd[0]
    assert "example.com" in cmd
