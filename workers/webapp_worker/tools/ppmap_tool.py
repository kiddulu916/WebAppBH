"""PpmapTool -- Prototype pollution scanning via ppmap CLI.

Runs ppmap against URLs whose tech_stack observations indicate a
JavaScript framework is in use (Node, Express, React, Vue, Angular,
Next, Nuxt, Gatsby).  Only executes when relevant JS frameworks are
detected, otherwise returns empty stats.
"""

from __future__ import annotations

import json

from sqlalchemy import select

from lib_webbh import Asset, Observation, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("ppmap")

# JS framework indicators to match in observations.tech_stack.
JS_FRAMEWORK_INDICATORS = [
    "node", "express", "react", "vue", "angular",
    "next", "nuxt", "gatsby",
]


class PpmapTool(WebAppTool):
    """Scan URLs with JS frameworks for prototype pollution using ppmap."""

    name = "ppmap"
    tool_type = ToolType.CLI
    weight_class = WeightClass.LIGHT

    # ------------------------------------------------------------------
    # Query helper
    # ------------------------------------------------------------------

    async def _get_js_framework_urls(
        self, target_id: int
    ) -> list[tuple[int, str]]:
        """Return ``[(asset_id, url), ...]`` for assets with JS frameworks.

        Joins Asset -> Observation, checks tech_stack JSON for framework
        name indicators.  Returns only distinct (asset_id, url) pairs.
        """
        async with get_session() as session:
            stmt = (
                select(Asset.id, Asset.asset_value)
                .join(Observation, Observation.asset_id == Asset.id)
                .where(Asset.target_id == target_id)
                .distinct()
            )
            result = await session.execute(stmt)
            rows = result.all()

        matched: list[tuple[int, str]] = []
        for asset_id, asset_value in rows:
            # Fetch the observation tech_stack for this asset
            async with get_session() as session:
                obs_stmt = (
                    select(Observation.tech_stack)
                    .where(Observation.asset_id == asset_id)
                )
                obs_result = await session.execute(obs_stmt)
                tech_stacks = [row[0] for row in obs_result.all() if row[0]]

            for tech_stack in tech_stacks:
                # tech_stack is stored as JSON dict or string
                stack_str = ""
                if isinstance(tech_stack, dict):
                    stack_str = json.dumps(tech_stack).lower()
                elif isinstance(tech_stack, str):
                    stack_str = tech_stack.lower()

                if any(fw in stack_str for fw in JS_FRAMEWORK_INDICATORS):
                    matched.append((asset_id, asset_value))
                    break  # one match per asset is enough

        return matched

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_output(stdout: str) -> list[str]:
        """Parse ppmap stdout for lines indicating prototype pollution.

        Returns a list of vulnerability description strings.
        """
        findings: list[str] = []
        for line in stdout.splitlines():
            line_lower = line.strip().lower()
            if not line_lower:
                continue
            if "vulnerable" in line_lower or "pollution" in line_lower:
                findings.append(line.strip())
        return findings

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Run ppmap against URLs with detected JS frameworks.

        Returns a stats dict with keys: found, in_scope, new,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="prototype_pollution")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping ppmap -- within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # 2. Get URLs with JS framework indicators
        urls = await self._get_js_framework_urls(target_id)
        if not urls:
            log.info("No JS-framework URLs found -- skipping ppmap")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        total_found = 0
        total_in_scope = 0
        total_new = 0

        sem = get_semaphore(self.weight_class)

        # 3. Scan each URL
        for asset_id, domain in urls:
            async with sem:
                scan_url = f"https://{domain}"
                cmd = ["ppmap", "-u", scan_url]

                try:
                    log.info(
                        f"Running ppmap against {domain}",
                        extra={"domain": domain},
                    )
                    stdout = await self.run_subprocess(cmd, timeout=120)

                    # 4. Parse results
                    findings = self.parse_output(stdout)
                    total_found += len(findings)

                    # 5. Save each finding
                    for finding_text in findings:
                        total_in_scope += 1

                        vuln_id = await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title=(
                                f"Prototype pollution detected on {domain}"
                            ),
                            description=(
                                f"ppmap detected a prototype pollution "
                                f"vulnerability on {domain}.\n\n"
                                f"Detail: {finding_text}\n"
                                f"URL: {scan_url}"
                            ),
                            poc=scan_url,
                        )
                        if vuln_id:
                            total_new += 1

                except Exception as exc:
                    log.warning(
                        f"ppmap failed on {domain}: {exc}",
                        extra={"domain": domain},
                    )

        # 6. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "found": total_found,
            "in_scope": total_in_scope,
            "new": total_new,
            "skipped_cooldown": False,
        }
        log.info("ppmap complete", extra=stats)
        return stats
