"""WafFingerprinter — Stage 4 WAF detection.

Sends normal and malicious-looking requests to live URLs, then checks
response headers and status codes for known WAF signatures.
"""

from __future__ import annotations

import re

import httpx

from lib_webbh import setup_logger
from lib_webbh.scope import ScopeManager

from workers.webapp_worker.base_tool import ToolType, WebAppTool
from workers.webapp_worker.concurrency import WeightClass

logger = setup_logger("waf-fingerprinter")

# Payload appended to the URL to trigger WAF rules.
WAF_TRIGGER = "?test=<script>alert(1)</script>"

# Mixed-type signature list:
#   - ("header:server"|"header:x-powered-by", waf_name, re.Pattern)  — match header value
#   - ("header_present", waf_name, header_name_str)                  — check header exists
WAF_SIGNATURES: list[tuple[str, str, re.Pattern | str]] = [
    ("header:server", "Cloudflare", re.compile(r"cloudflare", re.I)),
    ("header:server", "AkamaiGHost", re.compile(r"akamaighost", re.I)),
    ("header:server", "Sucuri", re.compile(r"sucuri", re.I)),
    ("header:server", "Imperva", re.compile(r"imperva|incapsula", re.I)),
    ("header:server", "AWS WAF", re.compile(r"awselb|aws", re.I)),
    ("header:x-powered-by", "ModSecurity", re.compile(r"modsecurity", re.I)),
    ("header_present", "Cloudflare", "cf-ray"),
    ("header_present", "Akamai", "x-akamai-request-id"),
    ("header_present", "Sucuri", "x-sucuri-id"),
    ("header_present", "StackPath", "x-sp-"),
]


class WafFingerprinter(WebAppTool):
    """Detect Web Application Firewalls via header fingerprinting."""

    name = "waf_fingerprinter"
    tool_type = ToolType.HTTP
    weight_class = WeightClass.LIGHT

    @staticmethod
    def _match_signatures(
        resp_headers: dict[str, str],
    ) -> list[str]:
        """Return list of WAF names detected from response headers."""
        lower_headers = {k.lower(): v for k, v in resp_headers.items()}
        detected: set[str] = set()

        for sig_type, waf_name, pattern in WAF_SIGNATURES:
            if sig_type.startswith("header:"):
                # pattern is a compiled regex — match against header value
                header_key = sig_type.split(":", 1)[1]
                header_val = lower_headers.get(header_key, "")
                if header_val and pattern.search(header_val):  # type: ignore[union-attr]
                    detected.add(waf_name)
            elif sig_type == "header_present":
                # pattern is a string — check if any header name contains it
                header_prefix = pattern  # type: ignore[assignment]
                for key in lower_headers:
                    if header_prefix in key:  # type: ignore[operator]
                        detected.add(waf_name)
                        break

        return sorted(detected)

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
        **kwargs,
    ) -> dict:
        """Fingerprint WAFs on live URLs.

        Returns a stats dict with keys: urls_checked, wafs_detected,
        skipped_cooldown.
        """
        log = logger.bind(target_id=target_id, asset_type="waf")

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping waf_fingerprinter -- within cooldown period")
            return {
                "urls_checked": 0,
                "wafs_detected": 0,
                "skipped_cooldown": True,
            }

        urls = await self._get_live_urls(target_id)
        if not urls:
            log.info("No live URLs found")
            return {
                "urls_checked": 0,
                "wafs_detected": 0,
                "skipped_cooldown": False,
            }

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
        wafs_detected = 0

        try:
            for asset_id, domain in urls:
                try:
                    base_url = f"https://{domain}"

                    # Normal request
                    normal_resp = await client.get(base_url)
                    normal_headers = dict(normal_resp.headers)

                    # Malicious-looking request to trigger WAF
                    trigger_resp = await client.get(
                        base_url, params={"test": "<script>alert(1)</script>"}
                    )
                    trigger_headers = dict(trigger_resp.headers)

                    urls_checked += 1

                    # Combine detections from both responses
                    all_detected: set[str] = set()
                    all_detected.update(self._match_signatures(normal_headers))
                    all_detected.update(self._match_signatures(trigger_headers))

                    # 403/406 on the malicious request is a WAF indicator
                    if trigger_resp.status_code in (403, 406):
                        all_detected.add("Unknown WAF (blocked)")

                    if all_detected:
                        wafs_detected += 1
                        waf_list = ", ".join(sorted(all_detected))
                        await self._save_observation(
                            asset_id=asset_id,
                            status_code=trigger_resp.status_code,
                            page_title=None,
                            tech_stack={"waf": list(sorted(all_detected))},
                            headers=trigger_headers,
                        )
                        log.info(
                            f"WAF detected on {domain}: {waf_list}",
                            extra={"domain": domain},
                        )

                except Exception as exc:
                    log.warning(
                        f"Failed to fingerprint WAF on {domain}: {exc}",
                        extra={"domain": domain},
                    )
        finally:
            if should_close:
                await client.aclose()

        await self.update_tool_state(target_id, container_name)

        stats = {
            "urls_checked": urls_checked,
            "wafs_detected": wafs_detected,
            "skipped_cooldown": False,
        }
        log.info("waf_fingerprinter complete", extra=stats)
        return stats
