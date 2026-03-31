# tests/test_database_jobstate_ext.py
import pytest
from datetime import datetime, timezone

pytestmark = pytest.mark.anyio


async def test_jobstate_new_fields(db_session):
    from lib_webbh.database import Target, JobState

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    job = JobState(
        target_id=target.id,
        container_name="info_gathering",
        status="running",
        current_section_id="4.1.3",
        queued_at=now,
        started_at=now,
    )
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)

    assert job.current_section_id == "4.1.3"
    assert job.queued_at is not None
    assert job.started_at is not None
    assert job.completed_at is None
    assert job.skipped is False
    assert job.skip_reason is None
    assert job.retry_count == 0


async def test_jobstate_skip(db_session):
    from lib_webbh.database import Target, JobState

    target = Target(company_name="TestCo", base_domain="target.com")
    db_session.add(target)
    await db_session.commit()

    job = JobState(
        target_id=target.id,
        container_name="identity_mgmt",
        status="complete",
        skipped=True,
        skip_reason="no credentials provided",
    )
    db_session.add(job)
    await db_session.commit()
    await db_session.refresh(job)

    assert job.skipped is True
    assert job.skip_reason == "no credentials provided"
