"""JsCrawler — Stage 1 browser-based JavaScript file discovery.

Navigates to each live URL with Playwright, captures all .js responses
(external scripts) via page.on("response"), extracts inline <script>
content, and saves everything to disk for downstream static analysis.
"""

from __future__ import annotations

import os
import re

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("js-crawler")

# Base directory for raw JS file storage.  Tests patch this to tmp_path.
JS_DIR = "/app/shared/raw"

# Characters that are unsafe in filenames.
_UNSAFE_CHARS = re.compile(r"[^\w.\-]")


def _sanitize_filename(url: str) -> str:
    """Convert a URL into a safe filesystem name."""
    # Strip protocol prefix
    name = re.sub(r"^https?://", "", url)
    return _UNSAFE_CHARS.sub("_", name)


class JsCrawler(WebAppTool):
    """Crawl pages via Playwright and save external + inline JS files."""

    name = "js_crawler"
    tool_type = ToolType.BROWSER
    weight_class = WeightClass.HEAVY

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Crawl all live URLs and save discovered JS files.

        Returns a stats dict with keys: js_files_saved, inline_scripts,
        domains_crawled, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="js")

        # 1. Cooldown check
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping js_crawler — within cooldown period")
            return {
                "js_files_saved": 0,
                "inline_scripts": 0,
                "domains_crawled": 0,
                "skipped_cooldown": True,
            }

        # 2. Get browser manager from kwargs
        browser_mgr = kwargs.get("browser")
        if browser_mgr is None:
            log.warning("No BrowserManager provided — skipping js_crawler")
            return {
                "js_files_saved": 0,
                "inline_scripts": 0,
                "domains_crawled": 0,
                "skipped_cooldown": False,
            }

        # 3. Get live URLs (assets with HTTP ports)
        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found — nothing to crawl")
            return {
                "js_files_saved": 0,
                "inline_scripts": 0,
                "domains_crawled": 0,
                "skipped_cooldown": False,
            }

        # 4. Create JS output directory
        js_dir = os.path.join(JS_DIR, str(target_id), "js")
        os.makedirs(js_dir, exist_ok=True)

        total_js_saved = 0
        total_inline = 0
        domains_crawled = 0

        # 5. Crawl each domain
        for asset_id, domain in urls:
            js_urls_found: list[str] = []

            # Try https first, fall back to http
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}"
                page = None
                try:
                    page = await browser_mgr.new_page(headers=headers)

                    # Register response handler to capture JS files
                    def _make_response_handler(
                        _js_dir: str, _js_urls: list[str],
                    ):
                        """Factory to capture variables in closure."""

                        async def _on_response(response):
                            resp_url = response.url
                            content_type = response.headers.get(
                                "content-type", ""
                            )
                            is_js = resp_url.endswith(".js") or (
                                "javascript" in content_type
                            )
                            if not is_js:
                                return
                            try:
                                body = await response.text()
                                filename = _sanitize_filename(resp_url) + ".js"
                                filepath = os.path.join(_js_dir, filename)
                                with open(filepath, "w", encoding="utf-8") as f:
                                    f.write(body)
                                _js_urls.append(resp_url)
                            except Exception:
                                pass

                        return _on_response

                    page.on(
                        "response",
                        _make_response_handler(js_dir, js_urls_found),
                    )

                    # Navigate
                    await page.goto(url, wait_until="networkidle")

                    # Extract inline scripts (script tags without src)
                    inline_scripts = await page.evaluate(
                        """() => {
                            return Array.from(
                                document.querySelectorAll('script:not([src])')
                            ).map(s => s.textContent).filter(t => t && t.trim());
                        }"""
                    )

                    # Save inline scripts
                    for i, script_text in enumerate(inline_scripts):
                        filename = f"inline_{_sanitize_filename(domain)}_{i}.js"
                        filepath = os.path.join(js_dir, filename)
                        with open(filepath, "w", encoding="utf-8") as f:
                            f.write(script_text)
                        total_inline += 1

                    # Save asset entries for each discovered JS URL
                    for js_url in js_urls_found:
                        await self._save_asset(
                            target_id, js_url, scope_manager,
                            source_tool=self.name,
                        )
                        total_js_saved += 1

                    domains_crawled += 1

                    # https succeeded — skip http fallback
                    break

                except Exception as exc:
                    log.warning(
                        f"Failed to crawl {url}: {exc}",
                        extra={"domain": domain, "scheme": scheme},
                    )
                    # If https failed, continue to try http
                    continue

                finally:
                    if page is not None:
                        await browser_mgr.release_page(page)

        # 6. Update tool state and return stats
        await self.update_tool_state(target_id, container_name)

        stats = {
            "js_files_saved": total_js_saved,
            "inline_scripts": total_inline,
            "domains_crawled": domains_crawled,
            "skipped_cooldown": False,
        }
        log.info("js_crawler complete", extra=stats)
        return stats
