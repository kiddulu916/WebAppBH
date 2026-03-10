"""NucleiTool — Stage 1 broad vulnerability scanning with Nuclei."""

from __future__ import annotations

import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import (
    Asset,
    CloudAsset,
    Observation,
    Vulnerability,
    get_session,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.vuln_scanner.base_tool import VulnScanTool
from workers.vuln_scanner.concurrency import WeightClass, get_semaphore
from workers.vuln_scanner.template_sync import (
    CUSTOM_TEMPLATES_DIR,
    TEMPLATES_DIR,
    sync_templates,
)

logger = setup_logger("nuclei-tool")

NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "3600"))
NUCLEI_RATE_LIMIT = int(os.environ.get("NUCLEI_RATE_LIMIT", "150"))
NUCLEI_BULK_SIZE = int(os.environ.get("NUCLEI_BULK_SIZE", "25"))
NUCLEI_CONCURRENCY = int(os.environ.get("NUCLEI_CONCURRENCY", "10"))

# Maps target_profile.oos_attacks entries to Nuclei exclude-tags
_OOS_TAG_MAP: dict[str, list[str]] = {
    "No DoS": ["dos"],
    "No Brute Force": ["brute-force", "bruteforce"],
}


class NucleiTool(VulnScanTool):
    """Broad vulnerability scanning via ProjectDiscovery Nuclei."""

    name = "nuclei"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_exclude_tags(target) -> list[str]:
        """Read target_profile.oos_attacks and return Nuclei -etags list."""
        profile = target.target_profile or {}
        oos_attacks: list[str] = profile.get("oos_attacks", [])
        exclude: list[str] = []
        for label in oos_attacks:
            mapped = _OOS_TAG_MAP.get(label)
            if mapped:
                exclude.extend(mapped)
        return exclude

    async def _build_target_list(self, target_id: int) -> list[str]:
        """Collect URLs from live assets, URL assets, and cloud assets."""
        seen: set[str] = set()
        targets: list[str] = []

        # Live HTTP(S) hosts
        for _asset_id, domain in await self._get_live_urls(target_id):
            url = f"https://{domain}"
            if url not in seen:
                seen.add(url)
                targets.append(url)

        # Discovered URL assets
        for _asset_id, url in await self._get_all_url_assets(target_id):
            if url not in seen:
                seen.add(url)
                targets.append(url)

        # Cloud assets with public URLs
        async with get_session() as session:
            stmt = select(CloudAsset.url).where(
                CloudAsset.target_id == target_id,
                CloudAsset.url.isnot(None),
            )
            result = await session.execute(stmt)
            for (cloud_url,) in result.all():
                if cloud_url and cloud_url not in seen:
                    seen.add(cloud_url)
                    targets.append(cloud_url)

        return targets

    async def _get_tech_tags(self, target_id: int) -> list[str]:
        """Extract technology names from observations for template filtering."""
        tech_names: set[str] = set()
        async with get_session() as session:
            stmt = (
                select(Observation.tech_stack)
                .join(Asset, Asset.id == Observation.asset_id)
                .where(
                    Asset.target_id == target_id,
                    Observation.tech_stack.isnot(None),
                )
            )
            result = await session.execute(stmt)
            for (tech_stack,) in result.all():
                if isinstance(tech_stack, dict):
                    for tech_name in tech_stack.keys():
                        tech_names.add(tech_name.lower())
                elif isinstance(tech_stack, list):
                    for item in tech_stack:
                        if isinstance(item, str):
                            tech_names.add(item.lower())
                        elif isinstance(item, dict) and "name" in item:
                            tech_names.add(item["name"].lower())
        return sorted(tech_names)

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
        """Run Nuclei against all known target URLs."""
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping nuclei -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # ---- 1. Sync templates ----
        await sync_templates(self.run_subprocess)

        # ---- 2. Build target list ----
        target_urls = await self._build_target_list(target_id)
        if not target_urls:
            log.info("No targets for nuclei scan")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        log.info(f"Nuclei scan starting with {len(target_urls)} targets")

        # Write targets to temp file
        targets_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="nuclei-targets-"
        )
        try:
            targets_file.write("\n".join(target_urls))
            targets_file.close()

            output_file = tempfile.NamedTemporaryFile(
                suffix=".jsonl", delete=False, prefix="nuclei-output-"
            )
            output_file.close()

            # ---- 3. Build nuclei command ----
            cmd: list[str] = [
                "nuclei",
                "-l", targets_file.name,
                "-t", TEMPLATES_DIR,
                "-t", CUSTOM_TEMPLATES_DIR,
                "-jsonl",
                "-o", output_file.name,
                "-rate-limit", str(NUCLEI_RATE_LIMIT),
                "-bulk-size", str(NUCLEI_BULK_SIZE),
                "-concurrency", str(NUCLEI_CONCURRENCY),
                "-silent",
                "-no-color",
            ]

            # ---- 4. Exclude tags based on target profile ----
            exclude_tags = self._build_exclude_tags(target)
            if exclude_tags:
                cmd.extend(["-etags", ",".join(exclude_tags)])

            # Custom headers
            for key, value in (headers or {}).items():
                cmd.extend(["-H", f"{key}: {value}"])

            # ---- Run scan ----
            sem = get_semaphore(self.weight_class)
            await sem.acquire()
            try:
                try:
                    await self.run_subprocess(cmd, timeout=NUCLEI_TIMEOUT)
                except Exception as exc:
                    log.error(f"Nuclei process failed: {exc}")
            finally:
                sem.release()

            # ---- 5. Parse JSONL output ----
            stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            if os.path.exists(output_file.name):
                with open(output_file.name) as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            finding = json.loads(line)
                        except json.JSONDecodeError:
                            log.warning("Skipping malformed JSONL line")
                            continue

                        template_id = finding.get("template-id", "unknown")
                        matched_at = finding.get("matched-at", "")
                        info = finding.get("info", {})
                        severity = (info.get("severity") or "info").lower()
                        title = info.get("name", template_id)
                        description = info.get("description", "")
                        tags_str = info.get("tags", "")
                        curl_command = finding.get("curl-command", "")

                        # Build PoC string from curl command
                        poc = curl_command if curl_command else matched_at

                        # Resolve asset_id for the matched URL
                        asset_id = await self._save_asset(
                            target_id,
                            matched_at,
                            scope_manager,
                            source_tool=f"nuclei:{template_id}",
                        )
                        if asset_id is None:
                            # Out of scope -- skip
                            continue

                        # ---- 6. Save finding as vulnerability ----
                        vuln_id = await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity=severity,
                            title=title,
                            description=description
                            or f"Nuclei template {template_id} matched at {matched_at}",
                            poc=poc,
                        )

                        # ---- 7. Update source_tool with template ID ----
                        await self._update_vulnerability(
                            vuln_id=vuln_id,
                            severity=severity,
                            poc=poc,
                            source_tool=f"nuclei:{template_id}",
                            description=description
                            or f"Nuclei template {template_id} matched at {matched_at}",
                        )

                        stats["found"] += 1
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        log.info(f"Nuclei finding: [{severity}] {title} at {matched_at}")

        finally:
            # Cleanup temp files
            for path in (targets_file.name, output_file.name):
                try:
                    os.unlink(path)
                except OSError:
                    pass

        await self.update_tool_state(target_id, container_name)
        log.info("Nuclei scan complete", extra=stats)
        return stats
