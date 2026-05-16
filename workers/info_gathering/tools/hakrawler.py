# workers/info_gathering/tools/hakrawler.py
"""Hakrawler wrapper — fast HTTP web crawling (WSTG-INFO-07)."""

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.execution_path_analyzer import CrawlResult
from workers.info_gathering.tools.url_classifier import classify_url

_DEPTH_MAP: dict[str, int] = {"low": 2, "medium": 3, "high": 5}


class Hakrawler(InfoGatheringTool):
    """Fast HTTP crawler — scope-enforced, intensity-aware."""

    async def execute(self, target_id: int, **kwargs) -> CrawlResult:
        host: str | None = kwargs.get("host")
        target = kwargs.get("target")
        if not host and target:
            host = target.base_domain
        if not host:
            return CrawlResult(tool="hakrawler", error="no host provided")

        scope_manager = kwargs.get("scope_manager")
        headers: dict = kwargs.get("headers") or {}
        rate_limiter = kwargs.get("rate_limiter")
        intensity: str = kwargs.get("intensity") or "low"

        depth = _DEPTH_MAP.get(intensity, 2)

        cmd = [
            "hakrawler",
            "-url", f"https://{host}",
            "-depth", str(depth),
        ]
        for key, value in headers.items():
            cmd += ["-h", f"{key}: {value}"]

        # ws_seeds are not forwarded to Hakrawler: its -url flag accepts a single seed
        # and it performs no JS execution. Katana handles WebSocket seed crawling.
        try:
            stdout = await self.run_subprocess(cmd, rate_limiter=rate_limiter)
        except Exception as exc:
            return CrawlResult(tool="hakrawler", error=str(exc))

        discovered: list[str] = []
        ws_found: list[str] = []

        for line in stdout.strip().splitlines():
            url = line.strip()
            if not url or not url.startswith(("http", "ws")):
                continue

            if scope_manager and not await self.scope_check(target_id, url, scope_manager):
                continue

            asset_type = classify_url(url)
            await self.save_asset(target_id, asset_type, url, "hakrawler",
                                  scope_manager=scope_manager)

            if asset_type == "websocket":
                ws_found.append(url)
            else:
                discovered.append(url)

        return CrawlResult(tool="hakrawler", urls=discovered, ws_urls=ws_found)
