# workers/info_gathering/fingerprint_aggregator.py
"""FingerprintAggregator: consolidates Stage 2 probe results into one summary Observation.

Stage 2 probes return ``ProbeResult`` objects containing per-slot signal hints.
The aggregator scores those signals (Task 1.2), writes a single summary
``Observation`` row (Task 1.3), and emits any info-leak ``Vulnerability`` rows
(Task 1.4). This module is the scaffold — concrete scoring/IO lands in later tasks.
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
