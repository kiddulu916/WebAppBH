"""CommentHarvester -- Stage 2 HTML/JS comment mining.

Harvests interesting comments from HTML pages (fetched live) and saved
JavaScript files on disk.  Comments that match security-relevant patterns
(credentials, internal IPs, dev annotations, email addresses) are saved as
observations and vulnerabilities.
"""

from __future__ import annotations

import os
import re

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("comment-harvester")

# Base directory for raw JS file storage.  Tests patch this to tmp_path.
JS_DIR = "/app/shared/raw"

# ---------------------------------------------------------------------------
# Comment extraction regexes
# ---------------------------------------------------------------------------
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
JS_SINGLE_COMMENT_RE = re.compile(r"//(.+?)$", re.MULTILINE)
JS_MULTI_COMMENT_RE = re.compile(r"/\*(.*?)\*/", re.DOTALL)

# ---------------------------------------------------------------------------
# Interesting-content patterns  (pattern, severity, label)
# ---------------------------------------------------------------------------
INTERESTING_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b", re.I), "low", "Dev annotation"),
    (re.compile(r"\b(password|passwd|secret|api[_-]?key|token)\s*[:=]", re.I), "medium", "Credential leak"),
    (re.compile(r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b"), "medium", "Internal IP"),
    (re.compile(r"\blocalhost\b", re.I), "low", "Localhost reference"),
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "low", "Email address"),
]


def _extract_comments(html: str) -> list[str]:
    """Return all HTML and JS comments found in *html*."""
    comments: list[str] = []
    for m in HTML_COMMENT_RE.finditer(html):
        comments.append(m.group(1).strip())
    for m in JS_SINGLE_COMMENT_RE.finditer(html):
        comments.append(m.group(1).strip())
    for m in JS_MULTI_COMMENT_RE.finditer(html):
        comments.append(m.group(1).strip())
    return comments


def _classify_comment(comment: str) -> list[tuple[str, str]]:
    """Return ``[(severity, label), ...]`` for each matching pattern."""
    hits: list[tuple[str, str]] = []
    for pattern, severity, label in INTERESTING_PATTERNS:
        if pattern.search(comment):
            hits.append((severity, label))
    return hits


class CommentHarvester(WebAppTool):
    """Mine HTML pages and saved JS files for security-relevant comments."""

    name = "comment_harvester"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Harvest interesting comments from live HTML and saved JS files.

        Returns a stats dict with keys: urls_checked, files_scanned,
        comments_found, interesting, skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="comments")

        # 1. Cooldown guard
        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping comment_harvester -- within cooldown period")
            return {
                "urls_checked": 0,
                "files_scanned": 0,
                "comments_found": 0,
                "interesting": 0,
                "skipped_cooldown": True,
            }

        urls_checked = 0
        files_scanned = 0
        comments_found = 0
        interesting = 0

        # 2. HTTP client (should_close fallback)
        client = kwargs.get("client")
        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=10.0,
                headers=headers or {},
                follow_redirects=True,
            )
            should_close = True

        try:
            # 3. Fetch live URLs and scan HTML
            urls = await self._get_live_urls(target_id)
            for asset_id, domain in urls:
                try:
                    resp = await client.get(f"https://{domain}")
                    html = resp.text
                    urls_checked += 1

                    comments = _extract_comments(html)
                    comments_found += len(comments)

                    for comment in comments:
                        hits = _classify_comment(comment)
                        if not hits:
                            continue

                        interesting += 1

                        # Pick highest severity from hits
                        severity = "medium" if any(s == "medium" for s, _ in hits) else "low"
                        labels = ", ".join(label for _, label in hits)

                        await self._save_observation(
                            asset_id=asset_id,
                            status_code=resp.status_code,
                            page_title=None,
                            tech_stack={"comment": comment[:500], "labels": labels},
                            headers=None,
                        )

                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity=severity,
                            title=f"Interesting comment on {domain}: {labels}",
                            description=(
                                f"Comment found in HTML/JS on {domain}: "
                                f"{comment[:300]}"
                            ),
                        )
                except Exception as exc:
                    log.warning(
                        f"Failed to harvest comments from {domain}: {exc}",
                        extra={"domain": domain},
                    )

            # 4. Scan saved JS files on disk (only if we have an asset to link to)
            js_dir = os.path.join(JS_DIR, str(target_id), "js")
            if urls and os.path.isdir(js_dir):
                js_asset_id = urls[0][0]
                for filename in os.listdir(js_dir):
                    if not filename.endswith(".js"):
                        continue
                    filepath = os.path.join(js_dir, filename)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                    except OSError:
                        continue

                    files_scanned += 1
                    comments = _extract_comments(content)
                    comments_found += len(comments)

                    for comment in comments:
                        hits = _classify_comment(comment)
                        if not hits:
                            continue

                        interesting += 1
                        severity = "medium" if any(s == "medium" for s, _ in hits) else "low"
                        labels = ", ".join(label for _, label in hits)

                        await self._save_observation(
                            asset_id=js_asset_id,
                            status_code=None,
                            page_title=None,
                            tech_stack={"file": filename, "comment": comment[:500], "labels": labels},
                            headers=None,
                        )

                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=js_asset_id,
                            severity=severity,
                            title=f"Interesting comment in {filename}: {labels}",
                            description=(
                                f"Comment found in JS file {filename}: "
                                f"{comment[:300]}"
                            ),
                        )
        finally:
            if should_close:
                await client.aclose()

        # 5. Update tool state
        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "files_scanned": files_scanned,
            "comments_found": comments_found,
            "interesting": interesting,
            "skipped_cooldown": False,
        }
        log.info("comment_harvester complete", extra=stats)
        return stats
