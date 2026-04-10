# workers/info_gathering/tools/application_mapper.py
"""ApplicationMapper — post-processing analysis to create an application map."""

from lib_webbh import Asset, Location, Observation, Parameter, get_session
from sqlalchemy import select
from workers.info_gathering.base_tool import InfoGatheringTool


class ApplicationMapper(InfoGatheringTool):
    """Analyze all gathered info to create a comprehensive application map."""

    async def execute(self, target_id: int, **kwargs):
        stats = {"found": 0, "mapped": 0}

        try:
            async with get_session() as session:
                assets = (
                    await session.execute(
                        select(Asset).where(Asset.target_id == target_id)
                    )
                ).scalars().all()

                locations = (
                    await session.execute(
                        select(Location).join(Asset).where(Asset.target_id == target_id)
                    )
                ).scalars().all()

                parameters = (
                    await session.execute(
                        select(Parameter).join(Asset).where(Asset.target_id == target_id)
                    )
                ).scalars().all()

                observations = (
                    await session.execute(
                        select(Observation).join(Asset).where(Asset.target_id == target_id)
                    )
                ).scalars().all()

            entry_points = self._identify_entry_points(assets, parameters, observations)
            execution_paths = self._map_execution_paths(assets, observations)
            tech_stack = self._build_tech_stack(observations, assets)

            app_map = {
                "entry_points": entry_points,
                "execution_paths": execution_paths,
                "tech_stack": tech_stack,
                "summary": {
                    "total_assets": len(assets),
                    "total_locations": len(locations),
                    "total_parameters": len(parameters),
                    "total_observations": len(observations),
                    "entry_point_count": len(entry_points),
                    "execution_path_count": len(execution_paths),
                    "technology_count": len(tech_stack),
                },
            }

            await self.save_observation(
                target_id,
                "application_map",
                app_map,
                "application_mapper",
            )

            stats["found"] = len(entry_points)
            stats["mapped"] = len(execution_paths)

        except Exception as e:
            logger = getattr(self, "log", None)
            if logger:
                logger.error(f"ApplicationMapper failed: {e}")

        return stats

    def _identify_entry_points(self, assets, parameters, observations):
        """Identify entry points: forms, API endpoints, file uploads."""
        entry_points = []

        for obs in observations:
            if obs.observation_type == "forms":
                for form in obs.data.get("forms", []):
                    entry_points.append({
                        "type": "form",
                        "url": form.get("action", ""),
                        "method": form.get("method", "GET"),
                        "fields": form.get("fields", []),
                    })

        for asset in assets:
            if asset.asset_type == "url":
                url = asset.asset_value
                if any(
                    path in url.lower()
                    for path in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"]
                ):
                    entry_points.append({
                        "type": "api_endpoint",
                        "url": url,
                    })

        for param in parameters:
            if any(
                name in param.param_name.lower()
                for name in ["file", "upload", "attachment", "document", "image"]
            ):
                entry_points.append({
                    "type": "file_upload",
                    "parameter": param.param_name,
                    "source_url": param.source_url,
                })

        return entry_points

    def _map_execution_paths(self, assets, observations):
        """Map execution paths from collected URLs."""
        paths = []
        url_assets = [a for a in assets if a.asset_type == "url"]

        path_groups = {}
        for asset in url_assets:
            url = asset.asset_value
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                path = parsed.path.rstrip("/")
                if path:
                    domain = parsed.netloc
                    if domain not in path_groups:
                        path_groups[domain] = []
                    path_groups[domain].append(path)
            except Exception:
                continue

        for domain, domain_paths in path_groups.items():
            paths.append({
                "domain": domain,
                "paths": sorted(set(domain_paths)),
                "path_count": len(set(domain_paths)),
            })

        return paths

    def _build_tech_stack(self, observations, assets):
        """Identify technology stack relationships."""
        technologies = set()

        for obs in observations:
            if obs.tech_stack:
                for tech in obs.tech_stack:
                    if isinstance(tech, dict):
                        technologies.add(tech.get("name", tech.get("value", "")))
                    elif isinstance(tech, str):
                        technologies.add(tech)

        return sorted(technologies)
