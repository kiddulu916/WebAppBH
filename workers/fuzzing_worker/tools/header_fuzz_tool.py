"""HeaderFuzzTool — Stage 4 HTTP header injection + content-type fuzzing."""
from __future__ import annotations
import asyncio

import aiohttp

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager
from workers.fuzzing_worker.base_tool import FuzzingTool
from workers.fuzzing_worker.concurrency import WeightClass, get_semaphore

logger = setup_logger("header-fuzz-tool")

INJECTION_HEADERS = [
    {"name": "X-Forwarded-For", "value": "127.0.0.1", "purpose": "Bypass IP-based restrictions"},
    {"name": "X-Original-URL", "value": "/admin", "purpose": "Bypass WAF path filters"},
    {"name": "X-Rewrite-URL", "value": "/admin", "purpose": "Bypass WAF path filters (alternate)"},
    {"name": "True-Client-IP", "value": "127.0.0.1", "purpose": "Bypass geo-fencing"},
    {"name": "X-Real-IP", "value": "127.0.0.1", "purpose": "Bypass IP allowlists"},
    {"name": "X-Forwarded-Host", "value": "localhost", "purpose": "Host header manipulation"},
]

CONTENT_TYPES = [
    "application/xml",
    "text/yaml",
    "text/xml",
    "application/x-www-form-urlencoded",
]

XXE_PROBE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe "xxe-canary">]>'
    '<root><data>&xxe;</data></root>'
)

XXE_INDICATORS = ["xxe-canary", "SYSTEM", "DOCTYPE", "entity", "xml parsing"]
ERROR_INDICATORS = ["stack trace", "traceback", "exception", "error"]


class HeaderFuzzTool(FuzzingTool):
    name = "header-fuzz"
    weight_class = WeightClass.LIGHT

    @staticmethod
    def is_significant_deviation(baseline_status: int, baseline_size: int,
                                  test_status: int, test_size: int) -> bool:
        if baseline_status != test_status:
            return True
        if baseline_size > 0:
            diff_ratio = abs(test_size - baseline_size) / baseline_size
            return diff_ratio > 0.10
        return test_size > 0

    async def _fetch(self, session: aiohttp.ClientSession, url: str,
                     extra_headers: dict | None = None,
                     method: str = "GET", body: str | None = None) -> tuple[int, int, str]:
        headers = dict(extra_headers or {})
        try:
            kwargs = {"headers": headers, "ssl": False,
                      "timeout": aiohttp.ClientTimeout(total=10)}
            if method == "POST" and body:
                kwargs["data"] = body
            async with session.request(method, url, **kwargs) as resp:
                content = await resp.text()
                return resp.status, len(content), content
        except Exception:
            return 0, 0, ""

    async def execute(self, target, scope_manager: ScopeManager, target_id: int,
                      container_name: str, headers: dict | None = None, **kwargs) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping header fuzz — within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        url_assets = await self._get_all_url_assets(target_id)
        if not url_assets:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        profile = target.target_profile or {}
        rate_limit = profile.get("rate_limit", 50)
        sem = asyncio.Semaphore(rate_limit)

        stats = {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        async with aiohttp.ClientSession(headers=headers or {}) as session:
            # Sub-task A: Header injection
            for asset_id, url in url_assets:
                baseline_status, baseline_size, _ = await self._fetch(session, url)
                if baseline_status == 0:
                    continue

                for header_def in INJECTION_HEADERS:
                    async with sem:
                        test_status, test_size, _ = await self._fetch(
                            session, url,
                            extra_headers={header_def["name"]: header_def["value"]},
                        )

                    if self.is_significant_deviation(baseline_status, baseline_size, test_status, test_size):
                        stats["found"] += 1
                        severity = "high" if baseline_status in (401, 403) and test_status == 200 else "low"
                        await self._save_vulnerability(
                            target_id, asset_id, severity,
                            f"Header bypass: {header_def['name']} on {url}",
                            f"{header_def['purpose']}. Baseline: {baseline_status}/{baseline_size}B → Test: {test_status}/{test_size}B",
                            poc=f"curl -H '{header_def['name']}: {header_def['value']}' {url}",
                        )

            # Sub-task B: Content-Type fuzzing
            for asset_id, url in url_assets:
                for ct in CONTENT_TYPES:
                    async with sem:
                        body = XXE_PROBE if "xml" in ct else ""
                        status, size, content = await self._fetch(
                            session, url,
                            extra_headers={"Content-Type": ct, "Accept": ct},
                            method="POST", body=body,
                        )

                    if status == 0:
                        continue

                    content_lower = content.lower()

                    if any(ind in content_lower for ind in XXE_INDICATORS):
                        stats["found"] += 1
                        await self._save_vulnerability(
                            target_id, asset_id, "critical",
                            f"Potential XXE via {ct} on {url}",
                            f"XXE canary reflected in response when Content-Type changed to {ct}",
                            poc=f"curl -X POST -H 'Content-Type: {ct}' -d '{XXE_PROBE}' {url}",
                        )
                    elif any(ind in content_lower for ind in ERROR_INDICATORS):
                        stats["found"] += 1
                        await self._save_vulnerability(
                            target_id, asset_id, "medium",
                            f"Verbose error via {ct} on {url}",
                            f"Error/stack trace exposed when Content-Type changed to {ct}",
                        )

        await self.update_tool_state(target_id, container_name)
        log.info("header fuzz complete", extra=stats)
        return stats
