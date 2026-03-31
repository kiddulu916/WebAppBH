# tests/test_database_chain.py
import pytest

pytestmark = pytest.mark.anyio


async def test_create_chain_finding(db_session):
    from lib_webbh.database import (
        Target, Vulnerability, EscalationContext, ChainFinding,
    )

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    vuln1 = Vulnerability(target_id=target.id, severity="high", title="SQLi")
    vuln2 = Vulnerability(target_id=target.id, severity="medium", title="IDOR")
    db_session.add_all([vuln1, vuln2])
    await db_session.commit()
    await db_session.refresh(vuln1)
    await db_session.refresh(vuln2)

    esc = EscalationContext(
        target_id=target.id,
        vulnerability_id=vuln1.id,
        access_type="admin_panel",
        access_method="SQLi token extraction",
        severity="critical",
    )
    db_session.add(esc)
    await db_session.commit()
    await db_session.refresh(esc)

    chain = ChainFinding(
        target_id=target.id,
        escalation_context_id=esc.id,
        chain_description="Step 1: SQLi extracts token. Step 2: IDOR via admin API.",
        entry_vulnerability_id=vuln1.id,
        linked_vulnerability_ids=[vuln1.id, vuln2.id],
        total_impact="Full admin access with data exfiltration",
        severity="critical",
    )
    db_session.add(chain)
    await db_session.commit()
    await db_session.refresh(chain)

    assert chain.id is not None
    assert chain.linked_vulnerability_ids == [vuln1.id, vuln2.id]
    assert chain.severity == "critical"
