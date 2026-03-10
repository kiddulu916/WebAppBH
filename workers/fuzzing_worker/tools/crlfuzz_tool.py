"""CrlfuzzTool -- Stage 5 CRLF injection fuzzing."""
from __future__ import annotations
import os
import tempfile

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("crlfuzz-tool")

# Patterns that indicate high-severity CRLF findings
SET_COOKIE_INDICATORS = ["set-cookie", "Set-Cookie"]
RESPONSE_SPLITTING_INDICATORS = ["%0d%0a%0d%0a", "\\r\\n\\r\\n", "\r\n\r\n"]


class CrlfuzzTool(FuzzingTool):
    name = "crlfuzz"
    weight_class = WeightClass.HEAVY

    def build_command(self, url: str, concurrency: int,
                      headers: dict | None = None,
                      output_file: str = "/tmp/crlfuzz.txt") -> list[str]:
        cmd = [
            "crlfuzz", "-u", url,
            "-o", output_file,
            "-s",
            "-c", str(concurrency),
        ]
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])
        return cmd

    @staticmethod
    def _classify_severity(vuln_line: str) -> str:
        """Determine severity based on CRLF injection type.

        - "high" if Set-Cookie injection or response splitting (double CRLF /
          body injection detected via %0d%0a patterns)
        - "medium" for header injection only
        """
        lower = vuln_line.lower()
        for indicator in SET_COOKIE_INDICATORS:
            if indicator.lower() in lower:
                return "high"
        for indicator in RESPONSE_SPLITTING_INDICATORS:
            if indicator.lower() in lower:
                return "high"
        return "medium"

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping crlfuzz -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        # Combine URL assets and live URLs for maximum coverage
        url_assets = await self._get_all_url_assets(target_id)
        live_urls = await self._get_live_urls(target_id)

        # Merge and deduplicate by (asset_id, url)
        seen: set[int] = set()
        combined: list[tuple[int, str]] = []
        for asset_id, url in url_assets + live_urls:
            if asset_id not in seen:
                seen.add(asset_id)
                combined.append((asset_id, url))

        if not combined:
            log.info("No URLs to test for CRLF injection")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)
        concurrency = min(rate_limit, 20)

        sem = get_semaphore(self.weight_class)
        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        for asset_id, url in combined:
            # Live URLs from _get_live_urls are domains, not full URLs
            test_url = url if url.startswith("http") else f"https://{url}"

            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
                out_file = tmp.name

            cmd = self.build_command(test_url, concurrency, headers, out_file)

            await sem.acquire()
            try:
                try:
                    await self.run_subprocess(cmd)
                except Exception as e:
                    log.error(f"crlfuzz failed on {test_url}: {e}")
                    continue
                finally:
                    vuln_lines: list[str] = []
                    if os.path.exists(out_file):
                        with open(out_file) as f:
                            vuln_lines = [
                                line.strip() for line in f.readlines()
                                if line.strip()
                            ]
                        os.unlink(out_file)
            finally:
                sem.release()

            stats["found"] += len(vuln_lines)

            for vuln_url in vuln_lines:
                severity = self._classify_severity(vuln_url)

                if severity == "high":
                    description = (
                        "CRLF injection with Set-Cookie injection or HTTP "
                        "response splitting detected"
                    )
                else:
                    description = "CRLF header injection detected"

                stats["in_scope"] += 1
                stats["new"] += 1
                await self._save_vulnerability(
                    target_id, asset_id, severity,
                    f"CRLF injection: {test_url}",
                    f"{description}. Vulnerable URL: {vuln_url}",
                    poc=f"curl -v '{vuln_url}'",
                )

        await self.update_tool_state(target_id, container_name)
        log.info("crlfuzz complete", extra=stats)
        return stats
