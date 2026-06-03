"""ServerlessProbe — serverless platform detection via response headers (WSTG-INFO-10)."""
from __future__ import annotations

from typing import Any

import aiohttp

from lib_webbh import setup_logger
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("stage9-serverless-probe")

# (header_lower, platform)
_HEADER_SIGNATURES: list[tuple[str, str]] = [
    ("x-amz-request-id",          "aws_lambda"),
    ("x-amz-executed-version",    "aws_lambda"),
    ("x-ms-request-id",           "azure_functions"),
    ("x-azure-ref",               "azure_functions"),
    ("function-execution-id",     "google_cloud_functions"),
    ("x-cloud-trace-context",     "google_cloud_functions"),
    ("x-vercel-id",               "vercel"),
    ("x-nf-request-id",           "netlify"),
]


class ServerlessProbe(InfoGatheringTool):
    """Detects serverless platforms via response header markers (WSTG-INFO-10)."""

    async def execute(self, target_id: int, **kwargs: Any) -> None:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return

        await self.acquire_rate_limit(kwargs.get("rate_limiter"))
        platform: str | None = None
        matched_headers: list[str] = []

        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    f"https://{host}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True,
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.warning("serverless_probe fetch failed", extra={"host": host, "error": str(exc)})
            headers = {}

        for hdr, plt in _HEADER_SIGNATURES:
            if hdr in headers:
                if platform is None:
                    platform = plt
                matched_headers.append(hdr)

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "serverless_probe",
                "host": host,
                "detected": platform is not None,
                "platform": platform or "none",
                "matched_headers": matched_headers,
            },
        )
