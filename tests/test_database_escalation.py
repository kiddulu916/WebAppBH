# tests/test_database_escalation.py
import pytest

pytestmark = pytest.mark.anyio


async def test_create_escalation_context(db_session):
    from lib_webbh.database import Target, Vulnerability, EscalationContext

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    vuln = Vulnerability(
        target_id=target.id, severity="critical", title="SQLi"
    )
    db_session.add(vuln)
    await db_session.commit()
    await db_session.refresh(vuln)

    esc = EscalationContext(
        target_id=target.id,
        vulnerability_id=vuln.id,
        access_type="admin_panel",
        access_method="SQLi to extract admin session token, replayed cookie",
        session_data="encrypted_session_blob",
        data_exposed="All user PII visible in admin panel",
        severity="critical",
        section_id="4.7.5",
    )
    db_session.add(esc)
    await db_session.commit()
    await db_session.refresh(esc)

    assert esc.id is not None
    assert esc.access_type == "admin_panel"
    assert esc.consumed_by_chain is False
    assert esc.chain_findings is None


async def test_escalation_consumed_by_chain(db_session):
    from lib_webbh.database import Target, Vulnerability, EscalationContext

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    vuln = Vulnerability(target_id=target.id, severity="high", title="IDOR")
    db_session.add(vuln)
    await db_session.commit()

    esc = EscalationContext(
        target_id=target.id,
        vulnerability_id=vuln.id,
        access_type="user_account",
        access_method="IDOR on /api/users/{id}",
        severity="high",
        consumed_by_chain=True,
        chain_findings={"additional_vulns": [101, 102]},
    )
    db_session.add(esc)
    await db_session.commit()
    await db_session.refresh(esc)

    assert esc.consumed_by_chain is True
    assert esc.chain_findings == {"additional_vulns": [101, 102]}
