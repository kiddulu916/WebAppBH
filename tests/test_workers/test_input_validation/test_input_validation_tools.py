import json
from unittest.mock import MagicMock

from workers.input_validation.concurrency import WeightClass


def test_reflected_xss_tester_is_light():
    from workers.input_validation.tools.reflected_xss_tester import ReflectedXssTester
    assert ReflectedXssTester.weight_class == WeightClass.LIGHT


def test_sqlmap_generic_is_heavy():
    from workers.input_validation.tools.sqlmap_generic_tool import SqlmapGenericTool
    assert SqlmapGenericTool.weight_class == WeightClass.HEAVY


def test_sqlmap_oracle_config():
    from workers.input_validation.tools.sqlmap_generic_tool import SqlmapOracleTool
    tool = SqlmapOracleTool()
    cmd = tool.build_command("http://example.com/page?id=1")
    assert "--dbms=Oracle" in cmd
    assert "--technique=BEUST" in cmd


def test_injection_payloads_available():
    from workers.input_validation.tools.reflected_xss_tester import ReflectedXssTester
    tool = ReflectedXssTester()
    xss_payloads = tool.get_injection_payloads("xss")
    assert len(xss_payloads) > 0
    assert "<script>" in xss_payloads[0]


def test_vulnerability_detection():
    from workers.input_validation.tools.reflected_xss_tester import ReflectedXssTester
    tool = ReflectedXssTester()
    response = "<script>alert('XSS')</script> reflected"
    assert tool.detect_vulnerability(response, "xss")
    sql_error = "You have an error in your SQL syntax"
    assert tool.detect_vulnerability(sql_error, "sqli")
