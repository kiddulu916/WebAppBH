import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from datetime import datetime


def test_chain_viability_enum():
    from workers.chain_worker.models import ChainViability
    assert ChainViability.VIABLE.value == "viable"
    assert ChainViability.PARTIAL.value == "partial"
    assert ChainViability.NOT_VIABLE.value == "not_viable"
    assert ChainViability.AWAITING_ACCOUNTS.value == "awaiting_accounts"


def test_chain_step_creation():
    from workers.chain_worker.models import ChainStep
    step = ChainStep(
        action="ssrf_probe",
        target="http://target.com/import",
        result="200 OK",
        timestamp=datetime.now().isoformat(),
        request={"method": "GET", "url": "http://target.com/import?url=http://169.254.169.254/"},
        response={"status": 200, "body": "iam-role-name"},
        screenshot_path="/evidence/step_1.png",
    )
    assert step.action == "ssrf_probe"
    assert step.request["method"] == "GET"
    assert step.screenshot_path == "/evidence/step_1.png"


def test_chain_step_optional_fields():
    from workers.chain_worker.models import ChainStep
    step = ChainStep(
        action="msf_check",
        target="192.168.1.1:22",
        result="vulnerable",
        timestamp=datetime.now().isoformat(),
    )
    assert step.request is None
    assert step.response is None
    assert step.screenshot_path is None


def test_chain_result_success():
    from workers.chain_worker.models import ChainResult, ChainStep
    step = ChainStep(
        action="test", target="t", result="ok",
        timestamp=datetime.now().isoformat(),
    )
    result = ChainResult(
        success=True,
        steps=[step],
        poc="curl http://target.com/exploit",
        chain_name="ssrf_cloud_compromise",
    )
    assert result.success is True
    assert len(result.steps) == 1
    assert result.poc.startswith("curl")


def test_chain_result_failure():
    from workers.chain_worker.models import ChainResult
    result = ChainResult(
        success=False, steps=[], poc=None,
        chain_name="info_to_access",
        failure_reason="No credentials found in config leak",
    )
    assert result.success is False
    assert result.failure_reason is not None


def test_evaluation_result():
    from workers.chain_worker.models import ChainViability, EvaluationResult
    er = EvaluationResult(
        viability=ChainViability.VIABLE,
        matched_preconditions=["ssrf_vuln_found", "cloud_asset_exists"],
        missing_preconditions=[],
        matched_findings={"ssrf_vuln_id": 42, "cloud_asset_id": 7},
    )
    assert er.viability == ChainViability.VIABLE
    assert len(er.matched_preconditions) == 2
    assert er.matched_findings["ssrf_vuln_id"] == 42


def test_evaluation_result_partial():
    from workers.chain_worker.models import ChainViability, EvaluationResult
    er = EvaluationResult(
        viability=ChainViability.PARTIAL,
        matched_preconditions=["ssrf_vuln_found"],
        missing_preconditions=["cloud_asset_exists"],
    )
    assert er.viability == ChainViability.PARTIAL
    assert "cloud_asset_exists" in er.missing_preconditions


def test_target_findings_grouping():
    from workers.chain_worker.models import TargetFindings
    tf = TargetFindings(
        target_id=1,
        vulnerabilities=[],
        assets=[],
        parameters=[],
        observations=[],
        locations=[],
        test_accounts=None,
    )
    assert tf.target_id == 1
    assert tf.test_accounts is None


def test_target_findings_with_accounts():
    from workers.chain_worker.models import TargetFindings, TestAccounts, AccountCreds
    accounts = TestAccounts(
        attacker=AccountCreds(username="attacker@test.com", password="pass1"),
        victim=AccountCreds(username="victim@test.com", password="pass2"),
    )
    tf = TargetFindings(
        target_id=1,
        vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[],
        test_accounts=accounts,
    )
    assert tf.test_accounts.attacker.username == "attacker@test.com"
    assert tf.test_accounts.victim.password == "pass2"


def test_target_findings_vulns_by_type():
    from workers.chain_worker.models import TargetFindings

    class FakeVuln:
        def __init__(self, title, severity, source_tool):
            self.title = title
            self.severity = severity
            self.source_tool = source_tool

    vulns = [
        FakeVuln("XSS in search", "high", "xss_finder"),
        FakeVuln("SSRF in import", "high", "ssrf_scanner"),
        FakeVuln("XSS in comment", "medium", "xss_finder"),
    ]
    tf = TargetFindings(
        target_id=1, vulnerabilities=vulns, assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    xss = tf.vulns_by_source("xss_finder")
    assert len(xss) == 2
    ssrf = tf.vulns_by_source("ssrf_scanner")
    assert len(ssrf) == 1


def test_target_findings_vulns_by_severity():
    from workers.chain_worker.models import TargetFindings

    class FakeVuln:
        def __init__(self, title, severity, source_tool):
            self.title = title
            self.severity = severity
            self.source_tool = source_tool

    vulns = [
        FakeVuln("Critical bug", "critical", "nmap"),
        FakeVuln("High bug", "high", "nmap"),
        FakeVuln("Low bug", "low", "nmap"),
    ]
    tf = TargetFindings(
        target_id=1, vulnerabilities=vulns, assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    crit = tf.vulns_by_severity("critical")
    assert len(crit) == 1
    high = tf.vulns_by_severity("high")
    assert len(high) == 1
