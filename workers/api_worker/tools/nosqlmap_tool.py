"""NosqlmapTool -- Stage 3 NoSQL injection testing with nosqlmap.

Wraps the nosqlmap CLI to test endpoints backed by MongoDB/CouchDB
for NoSQL injection and authentication bypass vulnerabilities.
"""

from __future__ import annotations

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("nosqlmap-tool")

# Technologies that suggest NoSQL backends
NOSQL_TECHS = ["mongodb", "couchdb", "express", "node"]


class NosqlmapTool(ApiTestTool):
    """Test endpoints for NoSQL injection using nosqlmap."""

    name = "nosqlmap"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, stdout: str) -> list[str]:
        """Extract lines containing ``[+]`` with injection/bypass indicators."""
        findings: list[str] = []
        for line in stdout.splitlines():
            stripped = line.strip()
            if "[+]" in stripped:
                findings.append(stripped)
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
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping nosqlmap -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        urls = await self._get_tech_filtered_urls(target_id, NOSQL_TECHS)
        if not urls:
            log.info("No NoSQL-backed URLs found")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        sem = get_semaphore(self.weight_class)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        for asset_id, url_val in urls:
            target_url = url_val if url_val.startswith("http") else f"https://{url_val}"

            cmd = [
                "python3", "/opt/nosqlmap/nosqlmap.py",
                "-u", target_url,
                "--attack", "1",
                "--auto",
            ]

            await sem.acquire()
            try:
                try:
                    stdout = await self.run_subprocess(cmd)
                except Exception as exc:
                    log.error(f"nosqlmap failed for {target_url}: {exc}")
                    continue
            finally:
                sem.release()

            findings = self.parse_output(stdout)
            stats["found"] += len(findings)

            for finding in findings:
                stats["in_scope"] += 1
                stats["new"] += 1
                await self._save_vulnerability(
                    target_id=target_id,
                    asset_id=asset_id,
                    severity="high",
                    title=f"NoSQL injection: {finding[:80]}",
                    description=finding,
                    poc=f"nosqlmap -u {target_url}",
                )

        await self.update_tool_state(target_id, container_name)
        log.info("nosqlmap complete", extra=stats)
        return stats
