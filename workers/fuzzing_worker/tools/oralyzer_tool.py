"""OralyzerTool -- Stage 5 open redirect detection."""
from __future__ import annotations
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, Parameter, get_session, setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("oralyzer-tool")

# Parameters commonly used for redirects
REDIRECT_PARAMS: set[str] = {
    "redirect", "url", "next", "return", "goto", "dest", "continue",
    "redir", "forward", "target", "rurl", "out", "view", "link",
    "callback", "return_to", "returnurl", "redirect_uri", "return_url",
    "redirect_url", "next_url", "destination", "src", "href",
}

# Subset of redirect params involved in OAuth flows -- higher severity
OAUTH_PARAMS: set[str] = {
    "redirect_uri", "callback", "return_to", "returnurl", "redirect_url",
}


class OralyzerTool(FuzzingTool):
    name = "oralyzer"
    weight_class = WeightClass.LIGHT

    async def _get_redirect_params(
        self, target_id: int,
    ) -> list[tuple[int, str, str, str]]:
        """Query parameters table joined with assets for redirect-related params.

        Returns list of (asset_id, asset_value, param_name, source_url) tuples.
        """
        async with get_session() as session:
            stmt = (
                select(
                    Parameter.asset_id,
                    Asset.asset_value,
                    Parameter.param_name,
                    Parameter.source_url,
                )
                .join(Asset, Asset.id == Parameter.asset_id)
                .where(
                    Asset.target_id == target_id,
                    Parameter.param_name.in_(REDIRECT_PARAMS),
                )
            )
            result = await session.execute(stmt)
            return [
                (row[0], row[1], row[2], row[3] or row[1])
                for row in result.all()
            ]

    @staticmethod
    def _build_test_url(base_url: str, param_name: str) -> str:
        """Build a URL with the redirect parameter for testing."""
        separator = "&" if "?" in base_url else "?"
        return f"{base_url}{separator}{param_name}=https://evil.com"

    def build_command(self, url: str,
                      output_file: str = "/tmp/oralyzer.txt") -> list[str]:
        return [
            "python", "/opt/oralyzer/oralyzer.py",
            "-u", url,
            "-o", output_file,
        ]

    @staticmethod
    def _is_vulnerable(output: str) -> bool:
        """Check oralyzer output for vulnerability indicators."""
        lower = output.lower()
        return "vulnerable" in lower or "open redirect" in lower

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping oralyzer -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        redirect_params = await self._get_redirect_params(target_id)
        if not redirect_params:
            log.info("No redirect parameters found to test")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        sem = get_semaphore(self.weight_class)
        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        for asset_id, asset_value, param_name, source_url in redirect_params:
            test_url = self._build_test_url(source_url, param_name)

            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
                out_file = tmp.name

            cmd = self.build_command(test_url, out_file)

            await sem.acquire()
            try:
                try:
                    await self.run_subprocess(cmd)
                except Exception as e:
                    log.error(f"oralyzer failed on {test_url}: {e}")
                    continue
                finally:
                    raw = ""
                    if os.path.exists(out_file):
                        with open(out_file) as f:
                            raw = f.read()
                        os.unlink(out_file)
            finally:
                sem.release()

            if not self._is_vulnerable(raw):
                continue

            stats["found"] += 1
            stats["in_scope"] += 1
            stats["new"] += 1

            # OAuth redirect params are higher severity
            severity = "high" if param_name.lower() in OAUTH_PARAMS else "medium"

            if severity == "high":
                description = (
                    f"Open redirect via OAuth parameter '{param_name}' -- "
                    f"potential OAuth redirect chain risk"
                )
            else:
                description = (
                    f"Open redirect via parameter '{param_name}'"
                )

            await self._save_vulnerability(
                target_id, asset_id, severity,
                f"Open redirect: {param_name} on {source_url}",
                f"{description}. Test URL: {test_url}",
                poc=f"curl -v '{test_url}'",
            )

        await self.update_tool_state(target_id, container_name)
        log.info("oralyzer complete", extra=stats)
        return stats
