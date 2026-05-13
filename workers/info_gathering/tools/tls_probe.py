# workers/info_gathering/tools/tls_probe.py
"""TLSProbe — TLS handshake fingerprint via the ``tlsx`` binary.

Captures JA3S, TLS version, cipher, cert issuer/SANs, ALPN. Emits ``edge``
signals when the cert issuer matches a known CDN (per
``CDN_CERT_ISSUERS`` in ``fingerprint_signatures``). Also carries a
``tls_summary`` non-slot payload the aggregator merges into the summary
Observation.
"""
from __future__ import annotations

import json
from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.fingerprint_signatures import CDN_CERT_ISSUERS


class TLSProbe(InfoGatheringTool):
    """Stage 2 TLS fingerprint probe."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(
                probe="tls", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        cmd = [
            "tlsx", "-u", f"{host}:443", "-json", "-silent",
            "-ja3s", "-tls-version", "-cipher", "-cn", "-an", "-alpn", "-issuer",
        ]
        try:
            stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
        except Exception as exc:
            return ProbeResult(probe="tls", obs_id=None, signals={}, error=str(exc))

        data: dict[str, Any] = {}
        for line in stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

        tls_summary: dict[str, Any] = {
            "ja3s": data.get("ja3s_hash"),
            "tls_version": data.get("tls_version"),
            "cert_issuer": data.get("issuer_cn"),
            "san": data.get("subject_an", []),
            "alpn": data.get("alpn", []),
        }
        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "tls", **tls_summary},
        )

        signals: dict[str, Any] = {"edge": [], "tls_summary": tls_summary}
        issuer = (data.get("issuer_cn") or "").lower()
        for needle, vendor in CDN_CERT_ISSUERS.items():
            if needle.lower() in issuer:
                signals["edge"].append({
                    "src": "tls.cert_issuer", "value": vendor, "w": 0.5,
                })
                break
        return ProbeResult(probe="tls", obs_id=obs_id, signals=signals)
