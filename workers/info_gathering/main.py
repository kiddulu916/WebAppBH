# workers/info_gathering/main.py
import asyncio
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, select, update

from lib_webbh import get_session, push_task, setup_logger
from lib_webbh.database import Asset, AssetSnapshot, Campaign, Target, JobState
from lib_webbh.diffing import compute_diff
from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.rate_limiter import RateLimiter, parse_rate_rule
from lib_webbh.scope import ScopeManager

from .pipeline import Pipeline

logger = setup_logger("info_gathering")

WORKER_TYPE = "info_gathering"
MAX_EXPANSION_ROUNDS = 5
MAX_ASSETS_PER_ROUND = 500

SHARED_CONFIG = Path("/app/shared/config")


def _load_playbook(target_id: int) -> dict | None:
    path = SHARED_CONFIG / str(target_id) / "playbook.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


async def _get_expansion_targets(target_id: int, scanned_values: set[str]) -> list[Asset]:
    """Find new in-scope or associated assets not yet scanned."""
    async with get_session() as session:
        stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.scope_classification.in_(["in-scope", "associated"]),
            Asset.asset_type.in_(["domain", "ip", "subdomain"]),
        )
        if scanned_values:
            stmt = stmt.where(Asset.asset_value.notin_(scanned_values))
        result = await session.execute(stmt)
        return list(result.scalars().all())


async def _run_expansion(target_id: int) -> None:
    """Iteratively expand scope by scanning newly discovered in-scope/associated assets."""
    scanned: set[str] = set()

    async with get_session() as session:
        target = await session.get(Target, target_id)
        if target and target.base_domain:
            scanned.add(target.base_domain)

    for round_num in range(1, MAX_EXPANSION_ROUNDS + 1):
        new_assets = await _get_expansion_targets(target_id, scanned)

        if not new_assets:
            logger.info("Expansion converged", extra={"target_id": target_id, "round": round_num})
            await push_task(f"events:{target_id}", {
                "event": "CAMPAIGN_COMPLETE",
                "target_id": target_id,
                "rounds_completed": round_num - 1,
                "reason": "converged",
            })
            return

        if len(new_assets) > MAX_ASSETS_PER_ROUND:
            logger.warning("Expansion paused", extra={"target_id": target_id, "count": len(new_assets)})
            await push_task(f"events:{target_id}", {
                "event": "EXPANSION_PAUSED",
                "target_id": target_id,
                "round": round_num,
                "queued_count": len(new_assets),
                "reason": "max_assets_exceeded",
            })
            return

        for asset in new_assets:
            scanned.add(asset.asset_value)
            await push_task(f"{WORKER_TYPE}_queue", {
                "target_id": target_id,
                "domain": asset.asset_value if asset.asset_type == "domain" else None,
                "expansion_round": round_num,
            })

        logger.info(f"Expansion round {round_num} queued", extra={"target_id": target_id, "count": len(new_assets)})
        await push_task(f"events:{target_id}", {
            "event": "ROUND_COMPLETE",
            "target_id": target_id,
            "round": round_num,
            "new_assets": len(new_assets),
        })

    logger.info("Expansion stopped — max rounds reached", extra={"target_id": target_id})
    await push_task(f"events:{target_id}", {
        "event": "CAMPAIGN_COMPLETE",
        "target_id": target_id,
        "rounds_completed": MAX_EXPANSION_ROUNDS,
        "reason": "max_rounds",
    })


async def _compute_and_emit_diff(target_id: int, scan_number: int) -> None:
    async with get_session() as session:
        snapshot = (await session.execute(
            select(AssetSnapshot).where(
                AssetSnapshot.target_id == target_id,
                AssetSnapshot.scan_number == scan_number,
            )
        )).scalar_one_or_none()

        if snapshot is None:
            logger.warning("No snapshot found for diff", extra={"target_id": target_id})
            return

        previous_hashes = snapshot.asset_hashes or {}
        assets = (await session.execute(
            select(Asset).where(Asset.target_id == target_id)
        )).scalars().all()
        current_hashes = {a.asset_value: f"{a.asset_type}:{a.source_tool}" for a in assets}

    diff = compute_diff(previous_hashes, current_hashes)
    await push_task(f"events:{target_id}", {
        "event": "RECON_DIFF",
        "scan_number": scan_number,
        "added": diff.added,
        "removed": diff.removed,
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
        expansion_round = message["payload"].get("expansion_round")
        logger.info("Job received", extra={"target_id": target_id})

        try:
            # DELETE + INSERT to avoid MultipleResultsFound in CheckpointMixin
            async with get_session() as session:
                await session.execute(
                    delete(JobState).where(
                        JobState.target_id == target_id,
                        JobState.container_name == WORKER_TYPE,
                    )
                )
                session.add(JobState(
                    target_id=target_id,
                    container_name=WORKER_TYPE,
                    status="RUNNING",
                    started_at=datetime.now(timezone.utc),
                ))
                await session.commit()

            async with get_session() as session:
                target = await session.get(Target, target_id)
            if target is None:
                logger.error("Target not found", extra={"target_id": target_id})
                r = get_redis()
                await r.xack(message["stream"], consumer_group, message["msg_id"])
                continue

            profile = target.target_profile or {"in_scope_domains": [f"*.{target.base_domain}"]}
            scope_manager = ScopeManager(profile)

            # Load campaign rate limits if set
            rate_limiter = None
            if target.campaign_id:
                async with get_session() as session:
                    campaign = await session.get(Campaign, target.campaign_id)
                    if campaign and campaign.rate_limits:
                        try:
                            rules = [parse_rate_rule(r) for r in campaign.rate_limits]
                            redis_client = get_redis()
                            rate_limiter = RateLimiter(redis_client, campaign.id, rules)
                        except (ValueError, KeyError) as e:
                            logger.warning(f"Failed to parse rate limits: {e}")

            playbook = _load_playbook(target_id)
            pipeline = Pipeline(target_id=target_id, container_name=WORKER_TYPE)
            await pipeline.run(target, scope_manager, playbook=playbook, rate_limiter=rate_limiter)

            if rescan and snapshot_scan_number is not None:
                await _compute_and_emit_diff(target_id, snapshot_scan_number)

            if not expansion_round:
                if target.campaign_id:
                    await _run_expansion(target_id)

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
            try:
                async with get_session() as session:
                    await session.execute(
                        update(JobState)
                        .where(JobState.target_id == target_id)
                        .where(JobState.container_name == WORKER_TYPE)
                        .values(status="FAILED", error=str(e)[:500])
                    )
                    await session.commit()
            except Exception:
                pass

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
