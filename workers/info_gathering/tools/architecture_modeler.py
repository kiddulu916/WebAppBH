# workers/info_gathering/tools/architecture_modeler.py
"""ArchitectureModeler wrapper — build architecture model from collected data."""

from workers.info_gathering.base_tool import InfoGatheringTool


class ArchitectureModeler(InfoGatheringTool):
    """Build application architecture model from gathered information."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        from lib_webbh.database import Asset, Observation
        from lib_webbh import get_session
        from sqlalchemy import select

        # Collect all assets and observations
        async with get_session() as session:
            asset_stmt = select(Asset).where(Asset.target_id == target_id)
            asset_result = await session.execute(asset_stmt)
            assets = asset_result.scalars().all()

            obs_stmt = select(Observation).where(Observation.target_id == target_id)
            obs_result = await session.execute(obs_stmt)
            observations = obs_result.scalars().all()

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
            if obs.observation_type == "technology_detection":
                techs = obs.data.get("technologies", [])
                model["technologies"].extend(techs)
            elif obs.observation_type == "port_scan":
                model["ports"].append(obs.data)
            elif obs.observation_type == "forms":
                model["forms"].extend(obs.data.get("forms", []))

        # Deduplicate
        model["technologies"] = list(set(model["technologies"]))

        await self.save_observation(
            target_id, "architecture_model",
            model,
            "architecture_modeler"
        )