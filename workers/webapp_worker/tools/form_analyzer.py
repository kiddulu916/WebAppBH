"""FormAnalyzer — Stage 4 HTML form security analysis.

Parses HTML responses for form elements and checks for missing CSRF
protection and insecure password field attributes.
"""

from __future__ import annotations

import re

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("form-analyzer")

# Regex patterns for form analysis.
FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)
CSRF_RE = re.compile(
    r'<input[^>]+(?:name=["\'](?:csrf|_token|authenticity_token|__RequestVerificationToken)["\']|type=["\']hidden["\'][^>]*name=["\'](?:csrf|_token|authenticity_token)["\'])',
    re.IGNORECASE,
)
PASSWORD_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE)
AUTOCOMPLETE_OFF_RE = re.compile(r'autocomplete=["\'](?:off|new-password)["\']', re.IGNORECASE)
METHOD_POST_RE = re.compile(r'method=["\']post["\']', re.IGNORECASE)


class FormAnalyzer(WebAppTool):
    """Detect form-level security issues (missing CSRF, insecure passwords)."""

    name = "form_analyzer"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _analyze_forms(html: str) -> list[str]:
        """Return list of form security issues found in *html*."""
        issues: list[str] = []

        for match in FORM_RE.finditer(html):
            form_content = match.group(0)

            # Only check POST forms for CSRF (GET forms are less risky)
            if METHOD_POST_RE.search(form_content):
                if not CSRF_RE.search(form_content):
                    issues.append("POST form missing CSRF token")

            # Check password fields for autocomplete
            if PASSWORD_RE.search(form_content):
                if not AUTOCOMPLETE_OFF_RE.search(form_content):
                    issues.append("Password field without autocomplete=off")

        return issues

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Analyze forms on live URLs for security issues.

        Returns a stats dict with keys: urls_checked, form_issues,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="forms")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping form_analyzer — within cooldown period")
            return {"urls_checked": 0, "form_issues": 0, "skipped_cooldown": True}

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {"urls_checked": 0, "form_issues": 0, "skipped_cooldown": False}

        client = kwargs.get("client")
        should_close = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=10.0,
                headers=headers or {},
                follow_redirects=True,
            )
            should_close = True

        urls_checked = 0
        issue_count = 0

        try:
            for asset_id, domain in urls:
                try:
                    resp = await client.get(f"https://{domain}")
                    urls_checked += 1

                    issues = self._analyze_forms(resp.text)
                    for issue in issues:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"{issue} on {domain}",
                            description=(
                                f"Form analysis on {domain} found: {issue}. "
                                f"This may allow CSRF attacks or credential theft."
                            ),
                        )
                        issue_count += 1

                except Exception as exc:
                    log.warning(
                        f"Failed to analyze forms on {domain}: {exc}",
                        extra={"domain": domain},
                    )
        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "form_issues": issue_count,
            "skipped_cooldown": False,
        }
        log.info("form_analyzer complete", extra=stats)
        return stats
