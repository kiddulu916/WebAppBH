# workers/info_gathering/tools/architecture_modeler.py
"""ArchitectureModeler wrapper — build architecture model from collected data."""

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class ArchitectureModeler(InfoGatheringTool):
    """Build application architecture model from gathered information."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or not asset_id:
            return

        from lib_webbh.database import Asset, Observation
        from lib_webbh import get_session
        from sqlalchemy import select

        try:
            # Collect all assets and observations (Observation links via asset_id, not target_id)
            async with get_session() as session:
                asset_stmt = select(Asset).where(Asset.target_id == target_id)
                asset_result = await session.execute(asset_stmt)
                assets = asset_result.scalars().all()

                asset_ids = [a.id for a in assets]
                obs_stmt = (
                    select(Observation).where(Observation.asset_id.in_(asset_ids))
                    if asset_ids else select(Observation).where(False)
                )
                obs_result = await session.execute(obs_stmt)
                observations = obs_result.scalars().all()
        except Exception as exc:
            logger.error("architecture_modeler DB query failed", target_id=target_id, error=str(exc))
            return

        # Build architecture model
        model = {
            "domains": [],
            "subdomains": [],
            "ips": [],
            "urls": [],
            "technologies": [],
            "ports": [],
            "forms": [],
        }

        for asset in assets:
            if asset.asset_type == "domain":
                model["domains"].append(asset.asset_value)
            elif asset.asset_type == "subdomain":
                model["subdomains"].append(asset.asset_value)
            elif asset.asset_type == "ip":
                model["ips"].append(asset.asset_value)
            elif asset.asset_type == "url":
                model["urls"].append(asset.asset_value)

        for obs in observations:
            tech = obs.tech_stack or {}
            probe = tech.get("_probe") or tech.get("_source") or ""
            if probe == "technology_detection":
                techs = tech.get("technologies", [])
                model["technologies"].extend(techs)
            elif probe == "port_scan":
                model["ports"].append(tech)
            elif probe == "forms":
                model["forms"].extend(tech.get("forms", []))

        # Deduplicate
        model["technologies"] = list(set(model["technologies"]))

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_source": "architecture_modeler", "model": model},
        )