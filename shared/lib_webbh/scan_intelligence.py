"""Adaptive scan intelligence (Task 4).

Tracks per-tool, per-tech-stack hit rates and generates adaptive playbooks
that skip low-yield tools and boost high-yield ones.

Public API
----------
- ``fingerprint_tech_stack(observations)`` -> deterministic short string
- ``record_tool_result(...)`` -> upserts a ``ToolHitRate`` row
- ``get_tool_rankings(tech_fingerprint)`` -> list[ToolRanking] sorted by hit rate
- ``generate_adaptive_playbook(tech_fingerprint, base)`` -> ``PlaybookConfig``

Adaptive playbook rules
-----------------------
1. **Cold start protection** — if total runs across all tools for the
   fingerprint is < ``COLD_START_RUNS`` (default 10), the base playbook is
   returned untouched.
2. **Skip rule** — any stage whose tool hit rate is < ``MIN_HIT_RATE``
   (default 0.01) is marked ``enabled=False``.
3. **Boost rule** — if any tool's confirmed hit rate is > ``BOOST_HIT_RATE``
   (default 0.20), bump concurrency.light by +2 (cap +4).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from sqlalchemy import func, select

from lib_webbh.database import ToolHitRate, get_session
from lib_webbh.playbooks import (
    ConcurrencyConfig,
    PlaybookConfig,
    StageConfig,
)


# ---------------------------------------------------------------------------
# Tunables (env-overridable)
# ---------------------------------------------------------------------------
COLD_START_RUNS = int(os.environ.get("ADAPTIVE_COLD_START_RUNS", "10"))
MIN_HIT_RATE = float(os.environ.get("ADAPTIVE_MIN_HIT_RATE", "0.01"))
BOOST_HIT_RATE = float(os.environ.get("ADAPTIVE_BOOST_HIT_RATE", "0.20"))


# ---------------------------------------------------------------------------
# ToolRanking dataclass
# ---------------------------------------------------------------------------
@dataclass
class ToolRanking:
    """A ranked entry returned by ``get_tool_rankings``."""

    tool_name: str
    total_runs: int
    total_findings: int
    confirmed_findings: int
    hit_rate: float           # total_findings / total_runs
    confirmed_rate: float     # confirmed_findings / total_runs
    avg_runtime_seconds: float


# ---------------------------------------------------------------------------
# Tech-stack fingerprinting
# ---------------------------------------------------------------------------
def fingerprint_tech_stack(observations: list[dict]) -> str:
    """Return a deterministic short fingerprint for a tech stack.

    The fingerprint is order-independent (observations are sorted) and
    normalized (lowercased, stripped, joined by ``|``). Empty observations
    return ``"unknown"``.
    """
    if not observations:
        return "unknown"

    parts: list[str] = []
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        value = obs.get("value")
        if not value:
            continue
        parts.append(str(value).strip().lower())

    if not parts:
        return "unknown"

    return "|".join(sorted(set(parts)))


# ---------------------------------------------------------------------------
# Recording tool results
# ---------------------------------------------------------------------------
async def record_tool_result(
    tech_fingerprint: str,
    tool_name: str,
    finding_count: int,
    confirmed: int,
    runtime_seconds: float,
) -> None:
    """Insert or update the ``ToolHitRate`` row for ``(fingerprint, tool)``.

    Maintains a running average for ``avg_runtime_seconds`` and bumps
    ``total_runs``, ``total_findings``, ``confirmed_findings``.
    """
    async with get_session() as session:
        row = (
            await session.execute(
                select(ToolHitRate).where(
                    ToolHitRate.tech_fingerprint == tech_fingerprint,
                    ToolHitRate.tool_name == tool_name,
                )
            )
        ).scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if row is None:
            session.add(
                ToolHitRate(
                    tech_fingerprint=tech_fingerprint,
                    tool_name=tool_name,
                    total_runs=1,
                    total_findings=int(finding_count),
                    confirmed_findings=int(confirmed),
                    avg_runtime_seconds=float(runtime_seconds),
                    last_hit_at=now,
                )
            )
        else:
            new_runs = row.total_runs + 1
            # Running mean: (old_mean * old_n + new_value) / new_n
            row.avg_runtime_seconds = (
                row.avg_runtime_seconds * row.total_runs + float(runtime_seconds)
            ) / new_runs
            row.total_runs = new_runs
            row.total_findings = row.total_findings + int(finding_count)
            row.confirmed_findings = row.confirmed_findings + int(confirmed)
            row.last_hit_at = now

        await session.commit()


# ---------------------------------------------------------------------------
# Rankings query
# ---------------------------------------------------------------------------
async def get_tool_rankings(tech_fingerprint: str) -> list[ToolRanking]:
    """Return all tools recorded for ``tech_fingerprint`` sorted by hit rate desc."""
    async with get_session() as session:
        rows = (
            (
                await session.execute(
                    select(ToolHitRate).where(
                        ToolHitRate.tech_fingerprint == tech_fingerprint
                    )
                )
            )
            .scalars()
            .all()
        )

    rankings: list[ToolRanking] = []
    for row in rows:
        runs = row.total_runs or 0
        hit_rate = (row.total_findings / runs) if runs else 0.0
        confirmed_rate = (row.confirmed_findings / runs) if runs else 0.0
        rankings.append(
            ToolRanking(
                tool_name=row.tool_name,
                total_runs=runs,
                total_findings=row.total_findings or 0,
                confirmed_findings=row.confirmed_findings or 0,
                hit_rate=hit_rate,
                confirmed_rate=confirmed_rate,
                avg_runtime_seconds=row.avg_runtime_seconds or 0.0,
            )
        )

    rankings.sort(key=lambda r: r.hit_rate, reverse=True)
    return rankings


# ---------------------------------------------------------------------------
# Adaptive playbook generation
# ---------------------------------------------------------------------------
async def generate_adaptive_playbook(
    tech_fingerprint: str,
    base: PlaybookConfig,
) -> PlaybookConfig:
    """Return an adapted copy of ``base`` for ``tech_fingerprint``.

    Applies the cold-start, skip and boost rules described in the module
    docstring. The base playbook is never mutated.
    """
    rankings = await get_tool_rankings(tech_fingerprint)
    total_runs = sum(r.total_runs for r in rankings)
    by_name: dict[str, ToolRanking] = {r.tool_name: r for r in rankings}

    new_stages: list[StageConfig] = []
    for stage in base.stages:
        new_stages.append(StageConfig(
            name=stage.name,
            enabled=stage.enabled,
            tool_timeout=stage.tool_timeout,
        ))

    new_concurrency = ConcurrencyConfig(
        heavy=base.concurrency.heavy,
        light=base.concurrency.light,
    )

    adapted = PlaybookConfig(
        name=f"{base.name}_adaptive",
        description=f"Adaptive variant of {base.name} for fingerprint={tech_fingerprint}",
        stages=new_stages,
        concurrency=new_concurrency,
    )

    # Cold-start protection — not enough data to adapt safely.
    if total_runs < COLD_START_RUNS:
        return adapted

    # Skip rule — disable stages whose tool has dismal hit rate.
    for stage in adapted.stages:
        ranking = by_name.get(stage.name)
        if ranking is None:
            continue
        # Only skip when we have a meaningful sample for *this* tool.
        if ranking.total_runs >= COLD_START_RUNS and ranking.hit_rate < MIN_HIT_RATE:
            stage.enabled = False

    # Boost rule — if any tool exceeds the boost threshold, raise light
    # concurrency by +2 (capped at base + 4).
    if any(
        r.confirmed_rate > BOOST_HIT_RATE and r.total_runs >= COLD_START_RUNS
        for r in rankings
    ):
        adapted.concurrency.light = min(
            base.concurrency.light + 4,
            adapted.concurrency.light + 2,
        )

    return adapted


__all__ = [
    "ToolRanking",
    "fingerprint_tech_stack",
    "record_tool_result",
    "get_tool_rankings",
    "generate_adaptive_playbook",
    "COLD_START_RUNS",
    "MIN_HIT_RATE",
    "BOOST_HIT_RATE",
]
