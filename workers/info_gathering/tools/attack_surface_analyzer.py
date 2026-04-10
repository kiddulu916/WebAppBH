# workers/info_gathering/tools/attack_surface_analyzer.py
"""AttackSurfaceAnalyzer — analyze collected attack surface to prioritize testing."""

from lib_webbh import Asset, Location, Observation, Parameter, get_session
from sqlalchemy import select
from workers.info_gathering.base_tool import InfoGatheringTool


class AttackSurfaceAnalyzer(InfoGatheringTool):
    """Analyze the attack surface to identify high-value targets and prioritize testing."""

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

            asset_counts = self._count_assets(assets)
            high_value = self._identify_high_value_targets(assets, observations, parameters)
            metrics = self._calculate_metrics(assets, locations, parameters, observations)
            priorities = self._prioritize_areas(high_value, metrics)

            analysis = {
                "asset_counts": asset_counts,
                "high_value_targets": high_value,
                "metrics": metrics,
                "priorities": priorities,
                "summary": (
                    f"Attack surface analysis: {metrics['total_assets']} assets, "
                    f"{metrics['total_locations']} locations, "
                    f"{metrics['total_parameters']} parameters, "
                    f"{len(high_value)} high-value targets identified. "
                    f"Priority areas: {', '.join(p['area'] for p in priorities[:3])}"
                ),
            }

            await self.save_observation(
                target_id,
                "attack_surface_analysis",
                analysis,
                "attack_surface_analyzer",
            )

            stats["found"] = len(high_value)
            stats["mapped"] = len(priorities)

        except Exception as e:
            logger = getattr(self, "log", None)
            if logger:
                logger.error(f"AttackSurfaceAnalyzer failed: {e}")

        return stats

    def _count_assets(self, assets):
        """Count and categorize all discovered assets."""
        counts = {}
        for asset in assets:
            asset_type = asset.asset_type
            counts[asset_type] = counts.get(asset_type, 0) + 1
        return counts

    def _identify_high_value_targets(self, assets, observations, parameters):
        """Identify high-value targets: admin panels, auth endpoints, APIs."""
        high_value = []

        admin_patterns = [
            "/admin", "/dashboard", "/manage", "/console", "/panel",
            "/wp-admin", "/phpmyadmin", "/cpanel", "/login",
        ]
        auth_patterns = [
            "/auth", "/oauth", "/sso", "/login", "/logout",
            "/signin", "/signup", "/register", "/password",
            "/token", "/session", "/jwt",
        ]
        api_patterns = [
            "/api/", "/graphql", "/rest/", "/v1/", "/v2/",
            "/rpc", "/soap", "/grpc",
        ]
        sensitive_patterns = [
            "/backup", "/config", "/debug", "/test", "/staging",
            "/dev", "/internal", "/private", "/secret",
            "/.env", "/.git", "/.svn", "/wp-config",
        ]

        for asset in assets:
            if asset.asset_type != "url":
                continue
            url = asset.asset_value.lower()

            for pattern in admin_patterns:
                if pattern in url:
                    high_value.append({
                        "type": "admin_panel",
                        "url": asset.asset_value,
                        "pattern_matched": pattern,
                        "priority": "critical",
                    })
                    break

            for pattern in auth_patterns:
                if pattern in url:
                    high_value.append({
                        "type": "auth_endpoint",
                        "url": asset.asset_value,
                        "pattern_matched": pattern,
                        "priority": "high",
                    })
                    break

            for pattern in api_patterns:
                if pattern in url:
                    high_value.append({
                        "type": "api_endpoint",
                        "url": asset.asset_value,
                        "pattern_matched": pattern,
                        "priority": "high",
                    })
                    break

            for pattern in sensitive_patterns:
                if pattern in url:
                    high_value.append({
                        "type": "sensitive_resource",
                        "url": asset.asset_value,
                        "pattern_matched": pattern,
                        "priority": "medium",
                    })
                    break

        return high_value

    def _calculate_metrics(self, assets, locations, parameters, observations):
        """Calculate attack surface metrics."""
        tech_count = 0
        for obs in observations:
            if obs.tech_stack:
                tech_count += len(obs.tech_stack)

        unique_ports = set()
        for loc in locations:
            if loc.port:
                unique_ports.add(loc.port)

        return {
            "total_assets": len(assets),
            "total_locations": len(locations),
            "total_parameters": len(parameters),
            "total_observations": len(observations),
            "unique_technologies": tech_count,
            "unique_ports": len(unique_ports),
            "attack_surface_score": len(assets) + len(locations) + len(parameters),
        }

    def _prioritize_areas(self, high_value, metrics):
        """Return prioritized list of areas to test."""
        priorities = []

        admin_count = sum(1 for t in high_value if t["type"] == "admin_panel")
        if admin_count > 0:
            priorities.append({
                "area": "Admin panels",
                "count": admin_count,
                "priority": "critical",
                "reason": "Admin interfaces often have elevated privileges",
            })

        auth_count = sum(1 for t in high_value if t["type"] == "auth_endpoint")
        if auth_count > 0:
            priorities.append({
                "area": "Authentication endpoints",
                "count": auth_count,
                "priority": "high",
                "reason": "Auth flows are common attack vectors",
            })

        api_count = sum(1 for t in high_value if t["type"] == "api_endpoint")
        if api_count > 0:
            priorities.append({
                "area": "API endpoints",
                "count": api_count,
                "priority": "high",
                "reason": "APIs often expose business logic and data",
            })

        sensitive_count = sum(1 for t in high_value if t["type"] == "sensitive_resource")
        if sensitive_count > 0:
            priorities.append({
                "area": "Sensitive resources",
                "count": sensitive_count,
                "priority": "medium",
                "reason": "May expose configuration or debug information",
            })

        if metrics["total_parameters"] > 10:
            priorities.append({
                "area": "Parameter fuzzing",
                "count": metrics["total_parameters"],
                "priority": "medium",
                "reason": "Large parameter surface increases injection risk",
            })

        if metrics["unique_ports"] > 5:
            priorities.append({
                "area": "Port analysis",
                "count": metrics["unique_ports"],
                "priority": "medium",
                "reason": "Multiple open ports expand attack surface",
            })

        return priorities
