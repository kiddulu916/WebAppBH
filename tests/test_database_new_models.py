"""Tests for the four new ORM models:
BountySubmission, ScheduledScan, ScopeViolation, CustomPlaybook.
"""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import tests._patch_logger  # noqa: E402, F401

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from lib_webbh.database import (
    get_engine,
    get_session,
    Base,
    Target,
    Vulnerability,
    BountySubmission,
    ScheduledScan,
    ScopeViolation,
    CustomPlaybook,
)

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# BountySubmission
# ---------------------------------------------------------------------------


async def test_bounty_submission_crud(db):
    """Create a BountySubmission and verify all fields persist."""
    async with get_session() as session:
        target = Target(company_name="BountyCorp", base_domain="bountycorp.com")
        session.add(target)
        await session.flush()

        vuln = Vulnerability(
            target_id=target.id,
            severity="high",
            title="IDOR on /api/users",
            source_tool="manual",
        )
        session.add(vuln)
        await session.flush()

        submission = BountySubmission(
            target_id=target.id,
            vulnerability_id=vuln.id,
            platform="hackerone",
            status="triaged",
            submission_url="https://hackerone.com/reports/123456",
            expected_payout=1500.0,
            actual_payout=None,
            notes="Awaiting triage team review",
        )
        session.add(submission)
        await session.commit()

        stmt = select(BountySubmission).where(BountySubmission.target_id == target.id)
        result = await session.execute(stmt)
        row = result.scalar_one()

        assert row.platform == "hackerone"
        assert row.status == "triaged"
        assert row.submission_url == "https://hackerone.com/reports/123456"
        assert row.expected_payout == 1500.0
        assert row.actual_payout is None
        assert row.notes == "Awaiting triage team review"
        assert row.target_id == target.id
        assert row.vulnerability_id == vuln.id


async def test_bounty_submission_importable():
    """BountySubmission is importable from lib_webbh."""
    from lib_webbh import BountySubmission as BS

    assert BS.__tablename__ == "bounty_submissions"


# ---------------------------------------------------------------------------
# ScheduledScan
# ---------------------------------------------------------------------------


async def test_scheduled_scan_crud(db):
    """Create a ScheduledScan and verify defaults and fields persist."""
    async with get_session() as session:
        target = Target(company_name="ScheduleCorp", base_domain="schedulecorp.com")
        session.add(target)
        await session.flush()

        scan = ScheduledScan(
            target_id=target.id,
            cron_expression="0 2 * * *",
        )
        session.add(scan)
        await session.commit()

        stmt = select(ScheduledScan).where(ScheduledScan.target_id == target.id)
        result = await session.execute(stmt)
        row = result.scalar_one()

        assert row.cron_expression == "0 2 * * *"
        assert row.playbook == "wide_recon"
        assert row.enabled is True
        assert row.last_run_at is None
        assert row.next_run_at is None


async def test_scheduled_scan_unique_constraint(db):
    """Duplicate (target_id, cron_expression) raises IntegrityError."""
    async with get_session() as session:
        target = Target(company_name="DupScanCorp", base_domain="dupscancorp.com")
        session.add(target)
        await session.flush()

        scan1 = ScheduledScan(
            target_id=target.id,
            cron_expression="0 3 * * *",
        )
        session.add(scan1)
        await session.commit()

    with pytest.raises(IntegrityError):
        async with get_session() as session:
            t_row = (
                await session.execute(
                    select(Target).where(Target.base_domain == "dupscancorp.com")
                )
            ).scalar_one()
            scan2 = ScheduledScan(
                target_id=t_row.id,
                cron_expression="0 3 * * *",
            )
            session.add(scan2)
            await session.commit()


async def test_scheduled_scan_importable():
    """ScheduledScan is importable from lib_webbh."""
    from lib_webbh import ScheduledScan as SS

    assert SS.__tablename__ == "scheduled_scans"


# ---------------------------------------------------------------------------
# ScopeViolation
# ---------------------------------------------------------------------------


async def test_scope_violation_crud(db):
    """Create a ScopeViolation and verify all fields persist."""
    async with get_session() as session:
        target = Target(company_name="ScopeCorp", base_domain="scopecorp.com")
        session.add(target)
        await session.flush()

        violation = ScopeViolation(
            target_id=target.id,
            tool_name="subfinder",
            input_value="evil.com",
            violation_type="out_of_scope_domain",
        )
        session.add(violation)
        await session.commit()

        stmt = select(ScopeViolation).where(ScopeViolation.target_id == target.id)
        result = await session.execute(stmt)
        row = result.scalar_one()

        assert row.tool_name == "subfinder"
        assert row.input_value == "evil.com"
        assert row.violation_type == "out_of_scope_domain"
        assert row.target_id == target.id


async def test_scope_violation_importable():
    """ScopeViolation is importable from lib_webbh."""
    from lib_webbh import ScopeViolation as SV

    assert SV.__tablename__ == "scope_violations"


# ---------------------------------------------------------------------------
# CustomPlaybook
# ---------------------------------------------------------------------------


async def test_custom_playbook_crud(db):
    """Create a CustomPlaybook and verify all fields persist."""
    async with get_session() as session:
        playbook = CustomPlaybook(
            name="stealth_recon",
            description="Low-noise reconnaissance playbook",
            stages=[
                {"name": "passive", "tools": ["subfinder", "crt_sh"]},
                {"name": "active", "tools": ["httpx"]},
            ],
            concurrency={"max_workers": 2, "weight": "light"},
        )
        session.add(playbook)
        await session.commit()

        stmt = select(CustomPlaybook).where(CustomPlaybook.name == "stealth_recon")
        result = await session.execute(stmt)
        row = result.scalar_one()

        assert row.name == "stealth_recon"
        assert row.description == "Low-noise reconnaissance playbook"
        assert len(row.stages) == 2
        assert row.stages[0]["name"] == "passive"
        assert row.concurrency["max_workers"] == 2


async def test_custom_playbook_unique_constraint(db):
    """Duplicate name raises IntegrityError."""
    async with get_session() as session:
        pb1 = CustomPlaybook(name="unique_pb")
        session.add(pb1)
        await session.commit()

    with pytest.raises(IntegrityError):
        async with get_session() as session:
            pb2 = CustomPlaybook(name="unique_pb")
            session.add(pb2)
            await session.commit()


async def test_custom_playbook_importable():
    """CustomPlaybook is importable from lib_webbh."""
    from lib_webbh import CustomPlaybook as CP

    assert CP.__tablename__ == "custom_playbooks"
