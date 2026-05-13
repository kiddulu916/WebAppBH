# workers/info_gathering/tools/liveness_probe.py
"""LivenessProbe — Stage 2 single-host HTTP liveness via the httpx binary.

Probes a narrow HTTP port list, writes one Location row per alive port and
one Observation with ``_probe='liveness'`` listing every alive port with its
status code and detected tech.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

# Common HTTP/S ports. Full TCP/UDP discovery is Stage 9's job.
HTTP_PORTS: list[int] = [80, 443, 8000, 8008, 8080, 8443, 4443, 8888]

# Ports that imply HTTPS for the Location.service field.
_HTTPS_PORTS = frozenset({443, 8443, 4443})


class LivenessProbe(InfoGatheringTool):
    """Stage 2 liveness probe — single host, common HTTP ports."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        _ = target_id
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(
                probe="liveness", obs_id=None, signals={},
                error="missing host or asset_id",
            )

        targets = "\n".join(f"{host}:{p}" for p in HTTP_PORTS)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(targets)
            input_file = f.name

        try:
            cmd = [
                "httpx", "-l", input_file, "-json", "-silent",
                "-status-code", "-tech-detect", "-no-color",
            ]
            try:
                stdout = await self.run_subprocess(
                    cmd, rate_limiter=kwargs.get("rate_limiter"),
                )
            except Exception as exc:
                return ProbeResult(
                    probe="liveness", obs_id=None, signals={}, error=str(exc),
                )

            alive: list[dict[str, Any]] = []
            for line in stdout.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                try:
                    port = int(data.get("port") or 0)
                except (TypeError, ValueError):
                    continue
                if not port:
                    continue
                alive.append({
                    "port": port,
                    "status_code": data.get("status_code"),
                    "tech": data.get("tech", []),
                    "url": data.get("url", ""),
                })
                service = "https" if port in _HTTPS_PORTS else "http"
                await self.save_location(
                    asset_id=asset_id, port=port, protocol="tcp",
                    service=service, state="open",
                )

            obs_id = await self.save_observation(
                asset_id=asset_id,
                tech_stack={"_probe": "liveness", "alive": alive, "host": host},
            )
            return ProbeResult(
                probe="liveness", obs_id=obs_id,
                signals={"alive_ports": [a["port"] for a in alive]},
            )
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)
