# workers/info_gathering/framework_fingerprint_aggregator.py
"""FrameworkFingerprintAggregator — Stage 8 signal scoring and disclosure (WSTG 4.1.8).

Mirrors FingerprintAggregator (fingerprint_aggregator.py) in structure.
Slots: framework, cms, language.
"""
from __future__ import annotations

from typing import Any

from workers.info_gathering.fingerprint_aggregator import ProbeResult

FRAMEWORK_WEIGHTS: dict[str, float] = {
    "meta_generator":   0.8,
    "header_framework": 0.7,
    "framework_files":  0.6,
    "wappalyzer":       0.6,
    "webanalyze":       0.6,
    "cookie_framework": 0.5,
}
CONFIDENCE_THRESHOLD: float = 0.5
FRAMEWORK_SLOTS: tuple[str, ...] = ("framework", "cms", "language")

__all__ = [
    "CONFIDENCE_THRESHOLD", "FRAMEWORK_SLOTS", "FRAMEWORK_WEIGHTS",
    "FrameworkFingerprintAggregator",
]


class FrameworkFingerprintAggregator:
    """Consolidates Stage 8 probe results into a summary Observation and Vulnerability rows."""

    def __init__(self, asset_id: int, target_id: int) -> None:
        self.asset_id = asset_id
        self.target_id = target_id

    def _score_slot(self, slot: str, results: list[ProbeResult]) -> dict[str, Any]:
        """Weight-accumulation scoring identical to FingerprintAggregator._score_slot."""
        totals: dict[str, float] = {}
        signals_by_vendor: dict[str, list[dict[str, Any]]] = {}
        for r in results:
            if r.error is not None:
                continue
            for sig in r.signals.get(slot, []):
                if not isinstance(sig, dict):
                    continue
                vendor = sig["value"]
                totals[vendor] = totals.get(vendor, 0.0) + sig["w"]
                signals_by_vendor.setdefault(vendor, []).append(sig)

        if not totals:
            return {"vendor": None, "confidence": 0.0, "signals": [], "conflict": False}

        sorted_v = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
        top_vendor, top_score = sorted_v[0]
        clamped = min(top_score, 1.0)
        above = [v for v, s in sorted_v if s >= CONFIDENCE_THRESHOLD]

        if top_score < CONFIDENCE_THRESHOLD:
            return {"vendor": None, "confidence": clamped,
                    "signals": [s for ss in signals_by_vendor.values() for s in ss],
                    "conflict": False}
        if len(above) > 1:
            return {"vendor": top_vendor, "confidence": clamped, "conflict": True,
                    "candidates": [
                        {"vendor": v, "confidence": min(s, 1.0), "signals": signals_by_vendor[v]}
                        for v, s in sorted_v if s >= CONFIDENCE_THRESHOLD
                    ]}
        return {"vendor": top_vendor, "confidence": clamped,
                "signals": signals_by_vendor[top_vendor], "conflict": False}

    async def write_summary(self, results: list[ProbeResult]) -> int | None:
        """Score all slots, write one _probe=framework_summary Observation."""
        partial = any(r.error is not None for r in results)
        fingerprint = {slot: self._score_slot(slot, results) for slot in FRAMEWORK_SLOTS}
        payload: dict[str, Any] = {
            "_probe": "framework_summary",
            "section_id": "4.1.8",
            "partial": partial,
            "fingerprint": fingerprint,
            "raw_probe_obs_ids": [r.obs_id for r in results if r.obs_id is not None],
        }
        from lib_webbh import get_session
        from lib_webbh.database import Observation
        async with get_session() as session:
            obs = Observation(asset_id=self.asset_id, tech_stack=payload)
            session.add(obs)
            await session.commit()
            await session.refresh(obs)
            return obs.id

    def _probe_sources_for_vendor(self, vendor: str, raw: dict[str, Any]) -> set[str]:
        """Return set of probe names in raw that detected vendor."""
        sources: set[str] = set()
        for key in ("header_framework", "meta_generator", "wappalyzer",
                    "webanalyze", "cookie_framework"):
            if vendor in (raw.get(key) or {}).get("all_vendors", []):
                sources.add(key)
        return sources

    def _version_from_raw(self, vendor: str, raw: dict[str, Any]) -> str | None:
        """First version string for vendor across version-bearing probe entries."""
        for key in ("header_framework", "meta_generator"):
            for sig in (raw.get(key) or {}).get("version_signals", []):
                if sig.get("vendor") == vendor and sig.get("version"):
                    return sig["version"]
        return None

    async def emit_disclosures(
        self, fingerprint: dict[str, Any], raw: dict[str, Any],
    ) -> list[int]:
        """Emit Vulnerability rows for framework disclosure findings.

        Corroboration: if >=2 probes detected the same vendor AND >=1 has a version,
        emit one LOW corroborated finding and skip individual INFO findings for that vendor.
        File-based findings (admin paths, info files) are always emitted independently.
        """
        vuln_ids: list[int] = []
        corroborated: set[str] = set()

        # Pass 1: corroboration check for cms + framework slots
        for slot in ("cms", "framework"):
            scored = fingerprint.get(slot) or {}
            vendor = scored.get("vendor")
            if not vendor or scored.get("confidence", 0.0) < CONFIDENCE_THRESHOLD:
                continue
            sources = self._probe_sources_for_vendor(vendor, raw)
            version = self._version_from_raw(vendor, raw)
            if len(sources) >= 2 and version:
                corroborated.add(vendor)
                obs_ids = [
                    v for v in [
                        (raw.get("header_framework") or {}).get("obs_id"),
                        (raw.get("meta_generator") or {}).get("obs_id"),
                    ] if v is not None
                ]
                vuln_ids.append(await self._save_vuln(
                    title=f"Corroborated {slot} version identification: {vendor} {version}",
                    severity="LOW",
                    evidence={"vendor": vendor, "version": version, "slot": slot,
                              "sources": list(sources), "probe_obs_ids": obs_ids},
                ))

        # Pass 2: individual header/meta version disclosure (non-corroborated only)
        for sig in (raw.get("header_framework") or {}).get("version_signals", []):
            if sig.get("vendor") not in corroborated:
                vuln_ids.append(await self._save_vuln(
                    title=f"Framework version disclosed via HTTP header: "
                          f"{sig['vendor']} {sig['version']}",
                    severity="INFO",
                    evidence={"vendor": sig["vendor"], "version": sig["version"],
                              "slot": sig.get("slot"),
                              "probe_obs_id": (raw.get("header_framework") or {}).get("obs_id")},
                ))
        for sig in (raw.get("meta_generator") or {}).get("version_signals", []):
            if sig.get("vendor") not in corroborated:
                vuln_ids.append(await self._save_vuln(
                    title=f"Framework version disclosed via generator meta tag: "
                          f"{sig['vendor']} {sig['version']}",
                    severity="INFO",
                    evidence={"vendor": sig["vendor"], "version": sig["version"],
                              "slot": sig.get("slot"),
                              "probe_obs_id": (raw.get("meta_generator") or {}).get("obs_id")},
                ))

        # Pass 3: file-based findings (independent of corroboration)
        ff = raw.get("framework_files") or {}
        for path in ff.get("admin_paths", []):
            vuln_ids.append(await self._save_vuln(
                title=f"CMS admin interface publicly accessible: {path}",
                severity="LOW",
                evidence={"path": path, "probe_obs_id": ff.get("obs_id")},
            ))
        for path in ff.get("info_file_paths", []):
            vuln_ids.append(await self._save_vuln(
                title=f"CMS information file accessible: {path}",
                severity="LOW",
                evidence={"path": path, "probe_obs_id": ff.get("obs_id")},
            ))

        return vuln_ids

    async def _save_vuln(self, *, title: str, severity: str,
                         evidence: dict[str, Any]) -> int:
        from lib_webbh import get_session
        from lib_webbh.database import Vulnerability
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=self.target_id, asset_id=self.asset_id,
                severity=severity, title=title,
                worker_type="info_gathering", section_id="4.1.8",
                stage_name="fingerprint_framework",
                source_tool="framework_fingerprint_aggregator",
                vuln_type="information_disclosure", evidence=evidence,
            )
            session.add(vuln)
            await session.commit()
            await session.refresh(vuln)
            return vuln.id
