from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_katana_is_heavy():
    from workers.recon_core.tools.katana import Katana
    assert Katana.weight_class == WeightClass.HEAVY


def test_katana_build_command_with_headers():
    from workers.recon_core.tools.katana import Katana
    tool = Katana()
    target = MagicMock(base_domain="example.com")
    headers = {"Cookie": "session=abc"}
    cmd = tool.build_command(target, headers=headers)
    assert "katana" in cmd[0]
    assert "-H" in cmd


def test_katana_parse_output():
    from workers.recon_core.tools.katana import Katana
    tool = Katana()
    output = "https://a.example.com/path1\nhttps://a.example.com/path2\n"
    results = tool.parse_output(output)
    assert len(results) == 2


def test_hakrawler_is_light():
    from workers.recon_core.tools.hakrawler import Hakrawler
    assert Hakrawler.weight_class == WeightClass.LIGHT


def test_waybackurls_is_light():
    from workers.recon_core.tools.waybackurls import Waybackurls
    assert Waybackurls.weight_class == WeightClass.LIGHT


def test_waybackurls_parse_output():
    from workers.recon_core.tools.waybackurls import Waybackurls
    tool = Waybackurls()
    output = "https://a.example.com/old-page\nhttps://a.example.com/api/v1\n"
    results = tool.parse_output(output)
    assert len(results) == 2


def test_gauplus_is_light():
    from workers.recon_core.tools.gauplus import Gauplus
    assert Gauplus.weight_class == WeightClass.LIGHT


def test_paramspider_is_light():
    from workers.recon_core.tools.paramspider import Paramspider
    assert Paramspider.weight_class == WeightClass.LIGHT


def test_paramspider_parse_output():
    from workers.recon_core.tools.paramspider import Paramspider
    tool = Paramspider()
    output = (
        "https://a.example.com/page?id=FUZZ\n"
        "https://a.example.com/search?q=FUZZ&lang=FUZZ\n"
    )
    results = tool.parse_output(output)
    assert any(r["param_name"] == "id" for r in results)
    assert any(r["param_name"] == "q" for r in results)
