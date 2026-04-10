"""Tests for the adaptive scan intelligence module (Task 4).

Covers:
- fingerprint_tech_stack: deterministic, normalized fingerprint string
- record_tool_result: upserts ToolHitRate row, accumulates totals + runtime
- get_tool_rankings: returns hit_rate-sorted list per tech fingerprint
- generate_adaptive_playbook: applies skip / boost / cold-start rules
"""

import pytest
from sqlalchemy import select

from lib_webbh.database import get_session
from lib_webbh.playbooks import (
    PlaybookConfig,
    StageConfig,
    ConcurrencyConfig,
)

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# fingerprint_tech_stack
# ---------------------------------------------------------------------------


def test_fingerprint_is_deterministic_and_normalized():
    """Same observations in different order produce the same fingerprint."""
    from lib_webbh.scan_intelligence import fingerprint_tech_stack

    obs_a = [
        {"key": "server", "value": "Apache/2.4"},
        {"key": "lang", "value": "PHP/8.1"},
        {"key": "db", "value": "MySQL 8.0"},
    ]
    obs_b = [
        {"key": "db", "value": "MySQL 8.0"},
        {"key": "lang", "value": "PHP/8.1"},
        {"key": "server", "value": "Apache/2.4"},
    ]

    fp_a = fingerprint_tech_stack(obs_a)
    fp_b = fingerprint_tech_stack(obs_b)
    assert fp_a == fp_b
    assert isinstance(fp_a, str) and len(fp_a) > 0


def test_fingerprint_empty_observations_returns_constant():
    """Empty observations -> stable 'unknown' fingerprint, not crash."""
    from lib_webbh.scan_intelligence import fingerprint_tech_stack

    fp = fingerprint_tech_stack([])
    assert fp == "unknown"


def test_fingerprint_different_stacks_differ():
    """Different stacks must produce different fingerprints."""
    from lib_webbh.scan_intelligence import fingerprint_tech_stack

    a = fingerprint_tech_stack([{"key": "server", "value": "nginx"}])
    b = fingerprint_tech_stack([{"key": "server", "value": "apache"}])
    assert a != b


# ---------------------------------------------------------------------------
# ToolHitRate model
# ---------------------------------------------------------------------------


async def test_tool_hit_rate_model_exists(db):
    """Model is importable and has the expected unique constraint."""
    from lib_webbh.database import ToolHitRate

    assert ToolHitRate.__tablename__ == "tool_hit_rates"
    cols = {c.name for c in ToolHitRate.__table__.columns}
    assert {
        "tech_fingerprint",
        "tool_name",
        "total_runs",
        "total_findings",
        "confirmed_findings",
        "avg_runtime_seconds",
        "last_hit_at",
    }.issubset(cols)


# ---------------------------------------------------------------------------
# record_tool_result
# ---------------------------------------------------------------------------


async def test_record_tool_result_creates_row(db):
    """First call inserts a row; second call updates totals + runtime average."""
    from lib_webbh.database import ToolHitRate
    from lib_webbh.scan_intelligence import record_tool_result

    await record_tool_result(
        tech_fingerprint="apache_php_mysql",
        tool_name="nuclei",
        finding_count=3,
        confirmed=1,
        runtime_seconds=12.0,
    )
    await record_tool_result(
        tech_fingerprint="apache_php_mysql",
        tool_name="nuclei",
        finding_count=2,
        confirmed=0,
        runtime_seconds=8.0,
    )

    async with get_session() as session:
        row = (
            await session.execute(
                select(ToolHitRate).where(
                    ToolHitRate.tech_fingerprint == "apache_php_mysql",
                    ToolHitRate.tool_name == "nuclei",
                )
            )
        ).scalar_one()

    assert row.total_runs == 2
    assert row.total_findings == 5
    assert row.confirmed_findings == 1
    # Running average of 12 and 8 == 10
    assert abs(row.avg_runtime_seconds - 10.0) < 1e-6
    assert row.last_hit_at is not None


# ---------------------------------------------------------------------------
# get_tool_rankings
# ---------------------------------------------------------------------------


async def test_get_tool_rankings_sorted_by_hit_rate(db):
    """Tools are returned with hit_rate desc."""
    from lib_webbh.scan_intelligence import record_tool_result, get_tool_rankings

    fp = "nginx_node_postgres"
    # nuclei: 5 findings / 10 runs = 50%
    for _ in range(10):
        await record_tool_result(fp, "nuclei", finding_count=0, confirmed=0, runtime_seconds=1.0)
    await record_tool_result(fp, "nuclei", finding_count=5, confirmed=5, runtime_seconds=1.0)

    # subfinder: 1 finding / 11 runs ≈ 9%
    for _ in range(10):
        await record_tool_result(fp, "subfinder", finding_count=0, confirmed=0, runtime_seconds=1.0)
    await record_tool_result(fp, "subfinder", finding_count=1, confirmed=1, runtime_seconds=1.0)

    rankings = await get_tool_rankings(fp)
    assert len(rankings) == 2
    assert rankings[0].tool_name == "nuclei"
    assert rankings[0].hit_rate > rankings[1].hit_rate
    assert rankings[1].tool_name == "subfinder"


async def test_get_tool_rankings_empty_returns_empty(db):
    """Unknown fingerprint -> empty list, not error."""
    from lib_webbh.scan_intelligence import get_tool_rankings

    rankings = await get_tool_rankings("never_seen_fp")
    assert rankings == []


# ---------------------------------------------------------------------------
# generate_adaptive_playbook
# ---------------------------------------------------------------------------


def _base_playbook() -> PlaybookConfig:
    return PlaybookConfig(
        name="wide_recon",
        description="test base",
        stages=[
            StageConfig(name="passive_discovery"),
            StageConfig(name="liveness_dns"),
            StageConfig(name="fingerprinting"),
        ],
        concurrency=ConcurrencyConfig(heavy=2, light=4),
    )


async def test_adaptive_playbook_cold_start_keeps_everything(db):
    """With <10 total runs the base playbook is returned untouched."""
    from lib_webbh.scan_intelligence import (
        generate_adaptive_playbook,
        record_tool_result,
    )

    fp = "cold_fp"
    await record_tool_result(fp, "nuclei", finding_count=0, confirmed=0, runtime_seconds=1.0)

    base = _base_playbook()
    adapted = await generate_adaptive_playbook(fp, base)

    assert adapted.name.startswith("wide_recon")
    # All stages preserved (cold start)
    assert [s.name for s in adapted.stages] == [s.name for s in base.stages]
    assert all(s.enabled for s in adapted.stages)


async def test_adaptive_playbook_skips_low_hit_rate_tools(db):
    """Tool with <1% hit rate after enough runs should be marked skipped."""
    from lib_webbh.scan_intelligence import (
        generate_adaptive_playbook,
        record_tool_result,
    )

    fp = "skip_fp"
    # 200 zero-finding runs of "fingerprinting" stage tool, 0 confirmed -> 0% hit rate
    for _ in range(200):
        await record_tool_result(
            fp, "fingerprinting", finding_count=0, confirmed=0, runtime_seconds=0.1
        )

    base = _base_playbook()
    adapted = await generate_adaptive_playbook(fp, base)

    fingerprinting_stage = next(s for s in adapted.stages if s.name == "fingerprinting")
    assert fingerprinting_stage.enabled is False


async def test_adaptive_playbook_boosts_high_hit_rate_concurrency(db):
    """A tool with >20% confirmed hit rate should boost concurrency."""
    from lib_webbh.scan_intelligence import (
        generate_adaptive_playbook,
        record_tool_result,
    )

    fp = "boost_fp"
    # 30 runs, 10 confirmed = 33% confirmed hit rate
    for _ in range(20):
        await record_tool_result(
            fp, "passive_discovery", finding_count=0, confirmed=0, runtime_seconds=1.0
        )
    for _ in range(10):
        await record_tool_result(
            fp, "passive_discovery", finding_count=2, confirmed=1, runtime_seconds=1.0
        )

    base = _base_playbook()
    adapted = await generate_adaptive_playbook(fp, base)

    assert adapted.concurrency.light > base.concurrency.light or \
           adapted.concurrency.heavy > base.concurrency.heavy
