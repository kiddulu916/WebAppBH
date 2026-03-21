"""Test vulnerability correlation engine."""
import pytest
from lib_webbh.correlation import correlate_findings, CorrelationGroup

def test_group_by_shared_asset():
    vulns = [
        {"id": 1, "asset_value": "app.example.com", "title": "XSS", "severity": "high"},
        {"id": 2, "asset_value": "app.example.com", "title": "CSRF", "severity": "medium"},
        {"id": 3, "asset_value": "api.example.com", "title": "IDOR", "severity": "high"},
    ]
    groups = correlate_findings(vulns)
    assert isinstance(groups, list)
    assert all(isinstance(g, CorrelationGroup) for g in groups)
    app_group = next(g for g in groups if "app.example.com" in g.shared_assets)
    assert len(app_group.vuln_ids) == 2
    assert 1 in app_group.vuln_ids
    assert 2 in app_group.vuln_ids

def test_single_vuln_no_group():
    vulns = [{"id": 1, "asset_value": "unique.example.com", "title": "SQLi", "severity": "critical"}]
    groups = correlate_findings(vulns)
    assert len(groups) == 1
    assert groups[0].vuln_ids == [1]

def test_composite_severity():
    vulns = [
        {"id": 1, "asset_value": "app.example.com", "title": "Info Disclosure", "severity": "low"},
        {"id": 2, "asset_value": "app.example.com", "title": "Auth Bypass", "severity": "medium"},
        {"id": 3, "asset_value": "app.example.com", "title": "RCE", "severity": "critical"},
    ]
    groups = correlate_findings(vulns)
    group = groups[0]
    assert group.composite_severity == "critical"

def test_empty_vulns():
    groups = correlate_findings([])
    assert groups == []
