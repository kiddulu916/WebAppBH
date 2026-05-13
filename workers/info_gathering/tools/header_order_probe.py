# workers/info_gathering/tools/header_order_probe.py
"""HeaderOrderProbe — raw-socket GET / to preserve response header order/casing.

aiohttp normalizes headers; we open a TLS socket and read the raw response
prefix so the on-wire order and case-style are visible. The probe doesn't
score signals — header order is a corroborating hint the aggregator uses
when banner-derived ID is ambiguous (future enhancement). The Observation
row is the durable artifact.
"""
from __future__ import annotations

import asyncio
import ssl
from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _detect_casing(header_names: list[str]) -> str:
    """Return Title-Case / lowercase / Mixed for a list of header names."""
    if not header_names:
        return "Mixed"
    if all(h.islower() for h in header_names):
        return "lowercase"
    if all(_is_title_dashed(h) for h in header_names):
        return "Title-Case"
    return "Mixed"


def _is_title_dashed(name: str) -> bool:
    """Title-Case-Dashed test (e.g., ``Content-Type`` ✓, ``content-type`` ✗).

    Single-letter parts like ``X-Cache``'s ``X`` are accepted: when ``p[1:]``
    is empty, ``"".islower()`` is False but the part is still Title-Case.
    """
    parts = name.split("-")
    return all(p and p[0].isupper() and (not p[1:] or p[1:].islower()) for p in parts)


class HeaderOrderProbe(InfoGatheringTool):
    """Stage 2 raw-socket header-order probe."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(
                probe="header_order", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        try:
            await self.acquire_rate_limit(kwargs.get("rate_limiter"))
            raw = await self._raw_get(host, port=443, tls=True)
        except Exception as exc:
            return ProbeResult(
                probe="header_order", obs_id=None, signals={}, error=str(exc),
            )

        headers_section = raw.split("\r\n\r\n", 1)[0]
        lines = headers_section.split("\r\n")[1:]  # drop status line
        order = [ln.split(":", 1)[0] for ln in lines if ":" in ln]
        casing = _detect_casing(order)

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "header_order", "order": order, "casing": casing},
        )
        return ProbeResult(
            probe="header_order", obs_id=obs_id,
            signals={"origin_server": [], "edge": []},
        )

    async def _raw_get(self, host: str, port: int = 443, tls: bool = True) -> str:
        """Open a (TLS) socket, issue ``GET /``, read up to 8 KiB of the prefix.

        TLS cert verification is intentionally disabled — fingerprinting must
        work against hosts with self-signed or expired certs. A passive MITM
        could forge the response headers; only the casing/order shape is
        used downstream (as a corroborating signal), so the risk is bounded.
        """
        ssl_ctx = None
        if tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
        try:
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: webbh\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(req.encode("ascii"))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(8192), timeout=10.0)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return data.decode("iso-8859-1", errors="replace")
