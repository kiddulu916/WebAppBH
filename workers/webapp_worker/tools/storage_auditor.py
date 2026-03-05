"""StorageAuditor — Stage 3 browser-based localStorage/sessionStorage audit.

Evaluates browser storage on live pages to detect sensitive data (tokens,
credentials, API keys) stored in localStorage or sessionStorage.
"""

from __future__ import annotations

import re

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("storage-auditor")

# Case-insensitive patterns that indicate sensitive data in storage keys.
SENSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"passwd", re.IGNORECASE),
    re.compile(r"jwt", re.IGNORECASE),
    re.compile(r"bearer", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"access[_-]?key", re.IGNORECASE),
]

# JavaScript evaluated in the page context to dump all storage entries.
STORAGE_DUMP_EXPR = """() => {
    const entries = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        entries.push({store: "localStorage", key: key, value: localStorage.getItem(key)});
    }
    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        entries.push({store: "sessionStorage", key: key, value: sessionStorage.getItem(key)});
    }
    return entries;
}"""


class StorageAuditor(WebAppTool):
    """Detect sensitive data stored in browser localStorage/sessionStorage."""

    name = "storage_auditor"
    tool_type = ToolType.BROWSER
    weight_class = WeightClass.HEAVY

    def _is_sensitive(self, key: str) -> bool:
        """Return True if *key* matches any sensitive pattern."""
        return any(p.search(key) for p in SENSITIVE_PATTERNS)

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Audit browser storage on live URLs for sensitive keys.

        Returns a stats dict with keys: urls_checked, sensitive_keys_found,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="storage")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping storage_auditor — within cooldown period")
            return {
                "urls_checked": 0,
                "sensitive_keys_found": 0,
                "skipped_cooldown": True,
            }

        # 2. Get browser manager
        browser_mgr = kwargs.get("browser")
        if browser_mgr is None:
            log.warning("No BrowserManager provided — skipping storage_auditor")
            return {
                "urls_checked": 0,
                "sensitive_keys_found": 0,
                "skipped_cooldown": False,
            }

        # 3. Get live URLs
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found — nothing to check")
            return {
                "urls_checked": 0,
                "sensitive_keys_found": 0,
                "skipped_cooldown": False,
            }

        urls_checked = 0
        sensitive_count = 0

        # 4. Iterate each domain
        for asset_id, domain in urls:
            page = None
            try:
                page = await browser_mgr.new_page(headers=headers)
                await page.goto(f"https://{domain}", wait_until="networkidle")

                entries = await page.evaluate(STORAGE_DUMP_EXPR)
                urls_checked += 1

                for entry in entries:
                    key = entry.get("key", "")
                    if self._is_sensitive(key):
                        store = entry.get("store", "unknown")
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"Sensitive data in browser storage: {key}",
                            description=(
                                f"The key '{key}' in {store} on {domain} "
                                f"matches a sensitive data pattern. Storing "
                                f"credentials or tokens in browser storage "
                                f"exposes them to XSS attacks."
                            ),
                        )
                        sensitive_count += 1

            except Exception as exc:
                log.warning(
                    f"Failed to audit storage on {domain}: {exc}",
                    extra={"domain": domain},
                )
            finally:
                if page is not None:
                    await browser_mgr.release_page(page)

        # 5. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "sensitive_keys_found": sensitive_count,
            "skipped_cooldown": False,
        }
        log.info("storage_auditor complete", extra=stats)
        return stats
