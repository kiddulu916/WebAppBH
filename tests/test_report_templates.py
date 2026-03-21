"""Test report template rendering."""
import pytest
from lib_webbh.report_templates import render_vuln_report, Platform

def test_render_hackerone_report():
    vuln = {
        "title": "Reflected XSS in Search",
        "severity": "high",
        "asset_value": "search.example.com",
        "description": "User input reflected without encoding",
        "poc": "https://search.example.com?q=<script>alert(1)</script>",
        "source_tool": "dalfox",
        "cvss_score": 7.5,
    }
    report = render_vuln_report(vuln, Platform.HACKERONE)
    assert "## Summary" in report
    assert "Reflected XSS in Search" in report
    assert "search.example.com" in report
    assert "## Steps to Reproduce" in report
    assert "## Impact" in report

def test_render_bugcrowd_report():
    vuln = {
        "title": "SQL Injection",
        "severity": "critical",
        "asset_value": "api.example.com",
        "description": "Unsanitized input in login endpoint",
        "poc": "sqlmap -u https://api.example.com/login --data='user=admin'",
        "source_tool": "sqlmap",
    }
    report = render_vuln_report(vuln, Platform.BUGCROWD)
    assert "SQL Injection" in report
    assert "api.example.com" in report

def test_render_report_missing_fields():
    vuln = {"title": "Missing Info Vuln", "severity": "low"}
    report = render_vuln_report(vuln, Platform.HACKERONE)
    assert "Missing Info Vuln" in report
    assert "N/A" in report
