# workers/info_gathering/main.py
import asyncio
import socket
from datetime import datetime, timezone

from sqlalchemy import select, update

from lib_webbh import get_session, push_task, setup_logger
from lib_webbh.database import Asset, AssetSnapshot, Campaign, Target, JobState
from lib_webbh.diffing import compute_diff
from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.rate_limiter import RateLimiter, parse_rate_rule
from lib_webbh.scope import ScopeManager

from .pipeline import STAGES
from .concurrency import get_semaphores, TOOL_WEIGHTS

logger = setup_logger("info_gathering")

WORKER_TYPE = "info_gathering"


async def run_pipeline(target_id: int):
    """Run all stages sequentially, tools within each stage concurrently."""
    heavy_sem, light_sem = get_semaphores()

    # Get target for scope checking
    async with get_session() as session:
        target = await session.get(Target, target_id)
        if not target:
            logger.error("Target not found", extra={"target_id": target_id})
            return

        profile = target.target_profile or {"in_scope_domains": [f"*.{target.base_domain}"]}
        scope_manager = ScopeManager(profile)

        # Load campaign rate limits if campaign is set
        rate_limiter = None
        if target.campaign_id:
            campaign = await session.get(Campaign, target.campaign_id)
            if campaign and campaign.rate_limits:
                try:
                    rules = [parse_rate_rule(r) for r in campaign.rate_limits]
                    redis_client = get_redis()
                    rate_limiter = RateLimiter(redis_client, campaign.id, rules)
                except (ValueError, KeyError) as e:
                    logger.warning(f"Failed to parse rate limits: {e}")

    for _, stage in enumerate(STAGES):
        logger.info("Stage started", extra={"stage": stage.name, "section_id": stage.section_id})

        # Update job state
        async with get_session() as session:
            await session.execute(
                update(JobState)
                .where(JobState.target_id == target_id)
                .where(JobState.container_name == WORKER_TYPE)
                .values(
                    current_phase=stage.name,
                    current_section_id=stage.section_id,
                    last_tool_executed=None,
                )
            )
            await session.commit()

        # Run tools concurrently within the stage
        async def run_tool(tool_cls):
            weight = TOOL_WEIGHTS.get(tool_cls.__name__, "LIGHT")
            sem = heavy_sem if weight == "HEAVY" else light_sem
            async with sem:
                try:
                    tool = tool_cls()
                    await tool.execute(
                        target_id, target=target,
                        scope_manager=scope_manager,
                        rate_limiter=rate_limiter,
                    )
                except Exception as tool_err:
                    logger.warning(f"Tool {tool_cls.__name__} failed", extra={"error": str(tool_err)})

        if stage.tools:
            await asyncio.gather(*(run_tool(t) for t in stage.tools))

        logger.info("Stage complete", extra={"stage": stage.name})


async def _compute_and_emit_diff(target_id: int, scan_number: int) -> None:
    """Compare current assets against the pre-rescan snapshot and emit diff event."""
    async with get_session() as session:
        snapshot = (await session.execute(
            select(AssetSnapshot).where(
                AssetSnapshot.target_id == target_id,
                AssetSnapshot.scan_number == scan_number,
            )
        )).scalar_one_or_none()

        if snapshot is None:
            logger.warning("No snapshot found for diff", extra={"target_id": target_id, "scan_number": scan_number})
            return

        previous_hashes = snapshot.asset_hashes or {}

        assets = (await session.execute(
            select(Asset).where(Asset.target_id == target_id)
        )).scalars().all()
        current_hashes = {a.asset_value: f"{a.asset_type}:{a.source_tool}" for a in assets}

    diff = compute_diff(previous_hashes, current_hashes)

    if diff.has_changes:
        logger.info("Rescan diff detected", extra={"target_id": target_id,
                    "added": len(diff.added), "removed": len(diff.removed)})
        await push_task(f"events:{target_id}", {
            "event": "RECON_DIFF",
            "scan_number": scan_number,
            "added": diff.added,
            "removed": diff.removed,
            "unchanged_count": len(diff.unchanged),
        })
    else:
        await push_task(f"events:{target_id}", {
            "event": "RECON_DIFF",
            "scan_number": scan_number,
            "added": [],
            "removed": [],
            "unchanged_count": len(diff.unchanged),
        })


async def main():
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"

    async for message in listen_priority_queues(
        f"{WORKER_TYPE}_queue", consumer_group, consumer_name
    ):
        target_id = message["payload"]["target_id"]
        rescan = message["payload"].get("rescan", False)
        snapshot_scan_number = message["payload"].get("snapshot_scan_number")
        logger.info("Job received", extra={"target_id": target_id})

        try:
            # Create/update job state
            async with get_session() as session:
                job = JobState(
                    target_id=target_id,
                    container_name=WORKER_TYPE,
                    status="RUNNING",
                    started_at=datetime.now(timezone.utc),
                )
                session.add(job)
                await session.commit()

            await run_pipeline(target_id)

            # Compute rescan diff if this was a rescan with a snapshot
            if rescan and snapshot_scan_number is not None:
                await _compute_and_emit_diff(target_id, snapshot_scan_number)

            # Mark complete
            async with get_session() as session:
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="COMPLETED", completed_at=datetime.now(timezone.utc))
                )
                await session.commit()

        except Exception as e:
            logger.error("Job failed", extra={"target_id": target_id, "error": str(e)})
            async with get_session() as session:
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.container_name == WORKER_TYPE)
                    .values(status="FAILED", error=str(e))
                )
                await session.commit()

        # ACK the message
        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
