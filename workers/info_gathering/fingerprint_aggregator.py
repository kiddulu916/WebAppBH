# workers/info_gathering/fingerprint_aggregator.py
"""FingerprintAggregator: consolidates Stage 2 probe results into one summary Observation.

Stage 2 probes return ``ProbeResult`` objects containing per-slot signal hints.
The aggregator scores those signals (``_score_slot``), writes a single summary
``Observation`` row (``write_summary``), and emits info-leak ``Vulnerability``
rows (``emit_info_leaks``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Intensity = Literal["low", "medium", "high"]

__all__ = [
    "CONFIDENCE_THRESHOLD",
    "FingerprintAggregator",
    "Intensity",
    "ProbeResult",
    "SLOTS",
    "WEIGHTS",
]

# Per-signal weights for the per-slot scoring rule. Vendor confidence is the
# clamped sum of matched-signal weights; a slot is reported only when its top
# vendor's sum >= CONFIDENCE_THRESHOLD.
WEIGHTS: dict[str, float] = {
    "banner.server":        0.6,
    "banner.x_powered_by":  0.6,
    "tls.cert_issuer":      0.5,
    "header_order":         0.3,
    "method_options":       0.2,
    "error_page_signature": 0.7,
    "waf_active":           0.9,
    "waf_passive":          0.4,
    "app_fingerprint":      0.5,
}

CONFIDENCE_THRESHOLD: float = 0.5

# Fingerprint slots, fixed vocabulary.
SLOTS: tuple[str, ...] = ("edge", "origin_server", "framework", "os", "tls", "waf")


@dataclass
class ProbeResult:
    """Return value of every Stage 2 probe.

    ``signals`` is a mapping ``{slot: [{"src": ..., "value": ..., "w": ...}, ...]}``
    plus optional non-slot keys (e.g. ``"_raw"``, ``"tls_summary"``) that the
    aggregator consumes for non-scoring data.
    """

    probe: str
    obs_id: int | None
    signals: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class FingerprintAggregator:
    """Consolidates Stage 2 probe results into one summary Observation."""

    def __init__(self, asset_id: int, target_id: int, intensity: Intensity = "low") -> None:
        self.asset_id = asset_id
        self.target_id = target_id
        self.intensity: Intensity = intensity

    def _score_slot(self, slot: str, results: list[ProbeResult]) -> dict[str, Any]:
        """Sum weights per (slot, vendor) across non-errored probes.

        **Consumer contract:** branch on ``slot["conflict"]`` *before* reading
        ``slot["signals"]``. The conflict branch returns ``candidates`` and
        deliberately omits ``signals`` — readers that grab ``slot["signals"]``
        unconditionally will KeyError on conflict slots.

        Returns one of three shapes:
          - decisive single vendor: ``{vendor, confidence, signals, conflict: False}``
          - conflict (≥2 vendors above threshold): ``{vendor, confidence, candidates, conflict: True}``
          - null-vendor (no vendor reached threshold): ``{vendor: None, confidence, signals, conflict: False}``
            where ``signals`` is the flat union across every collected vendor.
        """
        totals: dict[str, float] = {}
        signals_by_vendor: dict[str, list[dict[str, Any]]] = {}
        for r in results:
            if r.error is not None:
                continue
            for signal in r.signals.get(slot, []):
                vendor = signal["value"]
                weight = signal["w"]
                totals[vendor] = totals.get(vendor, 0.0) + weight
                signals_by_vendor.setdefault(vendor, []).append(signal)

        if not totals:
            return {"vendor": None, "confidence": 0.0, "signals": [], "conflict": False}

        sorted_vendors = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
        top_vendor, top_score = sorted_vendors[0]
        top_score_clamped = min(top_score, 1.0)

        above_threshold = [v for v, s in sorted_vendors if s >= CONFIDENCE_THRESHOLD]

        if top_score < CONFIDENCE_THRESHOLD:
            return {
                "vendor": None,
                "confidence": top_score_clamped,
                "signals": [s for sigs in signals_by_vendor.values() for s in sigs],
                "conflict": False,
            }

        if len(above_threshold) > 1:
            return {
                "vendor": top_vendor,
                "confidence": top_score_clamped,
                "conflict": True,
                "candidates": [
                    {
                        "vendor": v,
                        "confidence": min(s, 1.0),
                        "signals": signals_by_vendor[v],
                    }
                    for v, s in sorted_vendors if s >= CONFIDENCE_THRESHOLD
                ],
            }

        return {
            "vendor": top_vendor,
            "confidence": top_score_clamped,
            "signals": signals_by_vendor[top_vendor],
            "conflict": False,
        }

    def _merge_tls(self, results: list[ProbeResult]) -> dict[str, Any]:
        """Return the ``tls_summary`` payload from the first non-errored TLS probe."""
        for r in results:
            if r.probe == "tls" and r.error is None:
                return r.signals.get("tls_summary", {})
        return {}

    async def write_summary(self, results: list[ProbeResult]) -> int:
        """Score every slot, merge TLS, write one ``_probe=summary`` Observation."""
        partial = any(r.error is not None for r in results)
        # ``tls`` carries TLS-probe raw data, not scored signals, so skip it
        # here and let ``_merge_tls`` own that key.
        fingerprint: dict[str, Any] = {
            slot: self._score_slot(slot, results) for slot in SLOTS if slot != "tls"
        }
        fingerprint["tls"] = self._merge_tls(results)
        payload: dict[str, Any] = {
            "_probe": "summary",
            "intensity": self.intensity,
            "partial": partial,
            "fingerprint": fingerprint,
            "raw_probe_obs_ids": [r.obs_id for r in results if r.obs_id is not None],
        }
        return await self._save_summary_observation(payload=payload)

    async def _save_summary_observation(self, *, payload: dict[str, Any]) -> int:
        """Insert the consolidated summary Observation against ``self.asset_id``."""
        from lib_webbh import get_session
        from lib_webbh.database import Observation
        async with get_session() as session:
            obs = Observation(asset_id=self.asset_id, tech_stack=payload)
            session.add(obs)
            await session.commit()
            await session.refresh(obs)
            return obs.id

    async def emit_info_leaks(
        self, fingerprint: dict[str, Any], raw: dict[str, Any],
    ) -> list[int]:
        """Emit INFO/LOW Vulnerabilities for clear information disclosure.

        ``fingerprint`` is the scored slot map (``{slot: {vendor, ...}}``).
        ``raw`` is a per-probe dict the pipeline assembles from ``ProbeResult``
        signals so this method can read banner headers / error-page signatures
        without re-querying the DB. Per-probe keys are allowed to be missing —
        the pipeline preamble omits a probe's entry when its probe errored, so
        ``or {}`` defaults are load-bearing for partial-success runs.
        """
        from workers.info_gathering.fingerprint_signatures import (
            DEFAULT_ERROR_LEAKERS,
            INTERNAL_DEBUG_HEADERS,
        )

        vuln_ids: list[int] = []

        origin = fingerprint.get("origin_server") or {}
        if origin.get("vendor") and origin.get("version"):
            vuln_ids.append(await self._save_vuln(
                title="Server software and version disclosure",
                severity="INFO",
                evidence={
                    "vendor": origin["vendor"],
                    "version": origin["version"],
                    "probe_obs_id": (raw.get("banner") or {}).get("obs_id"),
                },
            ))

        banner = raw.get("banner") or {}
        x_powered_by = banner.get("x_powered_by")
        if x_powered_by:
            vuln_ids.append(await self._save_vuln(
                title="Framework disclosure via X-Powered-By",
                severity="INFO",
                evidence={
                    "header": "X-Powered-By",
                    "value": x_powered_by,
                    "probe_obs_id": banner.get("obs_id"),
                },
            ))

        err = raw.get("error_page_404") or {}
        if err.get("signature_match") in DEFAULT_ERROR_LEAKERS:
            vuln_ids.append(await self._save_vuln(
                title="Default error page exposes server internals",
                severity="LOW",
                evidence={
                    "signature": err["signature_match"],
                    "probe_obs_id": err.get("obs_id"),
                },
            ))

        banner_headers = banner.get("headers") or {}
        debug_hits = [h for h in banner_headers if h.lower() in INTERNAL_DEBUG_HEADERS]
        if debug_hits:
            vuln_ids.append(await self._save_vuln(
                title="Internal debug header exposed to public",
                severity="LOW",
                evidence={
                    "headers": debug_hits,
                    "probe_obs_id": banner.get("obs_id"),
                },
            ))

        return vuln_ids

    async def _save_vuln(self, *, title: str, severity: str, evidence: dict[str, Any]) -> int:
        """Insert one Vulnerability row tagged for Stage 2 / WSTG section 4.1.2."""
        from lib_webbh import get_session
        from lib_webbh.database import Vulnerability
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=self.target_id,
                asset_id=self.asset_id,
                severity=severity,
                title=title,
                worker_type="info_gathering",
                section_id="4.1.2",
                stage_name="web_server_fingerprint",
                source_tool="fingerprint_aggregator",
                vuln_type="information_disclosure",
                evidence=evidence,
            )
            session.add(vuln)
            await session.commit()
            await session.refresh(vuln)
            return vuln.id
