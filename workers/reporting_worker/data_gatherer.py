"""Stage 1: Gather all report data from the database."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from lib_webbh.database import (
    ApiSchema, Asset, CloudAsset, Location, Observation, Target, Vulnerability,
    get_session,
)
from workers.reporting_worker.models import ReportContext


async def gather_report_data(target_id: int, screenshot_base: str = "/app/shared/raw") -> ReportContext:
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one()

        vulns = (await session.execute(
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset).selectinload(Asset.locations))
        )).scalars().all()

        assets = (await session.execute(
            select(Asset)
            .where(Asset.target_id == target_id)
            .options(selectinload(Asset.locations))
        )).scalars().all()

        locations = (await session.execute(
            select(Location).join(Asset).where(Asset.target_id == target_id)
        )).scalars().all()

        observations = (await session.execute(
            select(Observation).join(Asset).where(Asset.target_id == target_id)
        )).scalars().all()

        cloud_assets = (await session.execute(
            select(CloudAsset).where(CloudAsset.target_id == target_id)
        )).scalars().all()

        api_schemas = (await session.execute(
            select(ApiSchema).where(ApiSchema.target_id == target_id)
        )).scalars().all()

    screenshot_map = _scan_screenshots(target_id, screenshot_base)

    return ReportContext(
        target_id=target_id,
        company_name=target.company_name,
        base_domain=target.base_domain,
        target_profile=target.target_profile or {},
        vulnerabilities=list(vulns),
        assets=list(assets),
        locations=list(locations),
        observations=list(observations),
        cloud_assets=list(cloud_assets),
        api_schemas=list(api_schemas),
        screenshot_map=screenshot_map,
    )


def _scan_screenshots(target_id: int, base: str) -> dict[int, list[str]]:
    """Scan the shared raw directory for screenshots, keyed by asset_id."""
    target_dir = Path(base) / str(target_id)
    result: dict[int, list[str]] = {}
    if not target_dir.is_dir():
        return result
    for img in target_dir.glob("**/*.png"):
        try:
            asset_id = int(img.stem.split("_")[0])
            result.setdefault(asset_id, []).append(str(img))
        except (ValueError, IndexError):
            continue
    return result
