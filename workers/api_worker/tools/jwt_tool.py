"""JwtTool -- Stage 2 JWT token analysis with jwt_tool.

Wraps the jwt_tool CLI to test for algorithm confusion, none-algorithm
attacks, kid path traversal, and other JWT vulnerabilities.  Each
confirmed finding is saved as a high-severity vulnerability.
"""

from __future__ import annotations

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.api_worker.base_tool import ApiTestTool
from workers.api_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("jwt-tool")

# Modes to test: at = all tests, pb = playbook
JWT_MODES = ["at", "pb"]


class JwtTool(ApiTestTool):
    """Analyse JWT tokens for known vulnerabilities using jwt_tool."""

    name = "jwt_tool"
    weight_class = WeightClass.HEAVY

    # ------------------------------------------------------------------
    # Command building
    # ------------------------------------------------------------------

    def build_command(self, token: str, mode: str) -> list[str]:
        """Build the jwt_tool CLI command list."""
        return [
            "python3", "/opt/jwt_tool/jwt_tool.py",
            "-t", token,
            "-M", mode,
        ]

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def parse_output(self, stdout: str) -> list[str]:
        """Extract lines containing ``[+]`` as vulnerability indicators."""
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
            log.info("Skipping jwt_tool -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        tokens = await self._get_jwt_tokens(target_id)
        if not tokens:
            log.info("No JWT tokens found")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        sem = get_semaphore(self.weight_class)
        stats: dict = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Deduplicate tokens
        seen_tokens: set[str] = set()

        for token in tokens:
            if token in seen_tokens:
                continue
            seen_tokens.add(token)

            for mode in JWT_MODES:
                cmd = self.build_command(token, mode)

                await sem.acquire()
                try:
                    try:
                        stdout = await self.run_subprocess(cmd)
                    except Exception as exc:
                        log.error(f"jwt_tool failed [{mode}]: {exc}")
                        continue
                finally:
                    sem.release()

                findings = self.parse_output(stdout)
                stats["found"] += len(findings)

                for finding in findings:
                    # Use first live URL asset or fall-back to None
                    urls = await self._get_api_urls(target_id)
                    asset_id = urls[0][0] if urls else None

                    if asset_id is not None:
                        stats["in_scope"] += 1
                        stats["new"] += 1
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="high",
                            title=f"JWT vulnerability: {finding[:80]}",
                            description=finding,
                            poc=f"Token: {token[:20]}...",
                        )

        await self.update_tool_state(target_id, container_name)
        log.info("jwt_tool complete", extra=stats)
        return stats
