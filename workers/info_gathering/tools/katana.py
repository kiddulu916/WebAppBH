# workers/info_gathering/tools/katana.py
"""Katana wrapper — web crawling and execution path discovery (WSTG-INFO-07)."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.execution_path_analyzer import CrawlResult
from workers.info_gathering.tools.url_classifier import classify_url

_DEPTH_MAP: dict[str, int] = {"low": 2, "medium": 3, "high": 5}


class Katana(InfoGatheringTool):
    """Web crawler — JS-aware, form-following, scope-enforced."""

    async def execute(self, target_id: int, **kwargs) -> CrawlResult:
        host: str | None = kwargs.get("host")
        target = kwargs.get("target")
        if not host and target:
            host = target.base_domain
        if not host:
            return CrawlResult(tool="katana", error="no host provided")

        scope_manager = kwargs.get("scope_manager")
        headers: dict = kwargs.get("headers") or {}
        rate_limiter = kwargs.get("rate_limiter")
        intensity: str = kwargs.get("intensity") or "low"
        ws_seeds: list[str] = kwargs.get("ws_seeds") or []

        depth = _DEPTH_MAP.get(intensity, 2)

        # Seed URLs: primary host + any WebSocket endpoints from Stage 6
        seed_urls = [f"https://{host}"] + list(ws_seeds)

        cmd = [
            "katana",
            "-j",       # JSON output
            "-silent",  # suppress progress
            "-jc",      # enable JS file endpoint parsing
            "-headless",        # full headless JS rendering
            "-passive",         # passive JS execution
            "-form-extraction", # extract and follow forms
            "-d", str(depth),
        ]
        for url in seed_urls:
            cmd += ["-u", url]
        for key, value in headers.items():
            cmd += ["-H", f"{key}: {value}"]

        try:
            stdout = await self.run_subprocess(cmd, timeout=900, rate_limiter=rate_limiter)
        except Exception as exc:
            return CrawlResult(tool="katana", error=str(exc))

        discovered: list[str] = []
        ws_found: list[str] = []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            url = ""
            try:
                data = json.loads(line)
                url = data.get("url", "")
            except json.JSONDecodeError:
                if line.startswith(("http", "ws")):
                    url = line

            if not url:
                continue

            if scope_manager and not await self.scope_check(target_id, url, scope_manager):
                continue

            asset_type = classify_url(url)
            await self.save_asset(target_id, asset_type, url, "katana",
                                  scope_manager=scope_manager)

            if asset_type == "websocket":
                ws_found.append(url)
            else:
                discovered.append(url)

        return CrawlResult(tool="katana", urls=discovered, ws_urls=ws_found)
