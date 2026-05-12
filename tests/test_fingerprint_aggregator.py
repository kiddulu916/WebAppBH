# tests/test_fingerprint_aggregator.py
"""Tests for the Stage 2 FingerprintAggregator and ProbeResult dataclass."""
from workers.info_gathering.fingerprint_aggregator import (
    CONFIDENCE_THRESHOLD,
    FingerprintAggregator,
    ProbeResult,
    SLOTS,
    WEIGHTS,
)


class TestWeights:
    def test_weights_table_contains_required_keys(self):
        for key in ("banner.server", "banner.x_powered_by", "tls.cert_issuer",
                    "header_order", "method_options", "error_page_signature",
                    "waf_active", "waf_passive", "app_fingerprint"):
            assert key in WEIGHTS


class TestSlots:
    def test_slots_cover_full_vocabulary(self):
        assert set(SLOTS) == {"edge", "origin_server", "framework", "os", "tls", "waf"}


class TestConfidenceThreshold:
    def test_confidence_threshold_is_half(self):
        assert CONFIDENCE_THRESHOLD == 0.5


class TestProbeResult:
    def test_probe_result_default_no_error(self):
        r = ProbeResult(probe="banner", obs_id=1, signals={"server": "nginx"})
        assert r.error is None
        assert r.signals == {"server": "nginx"}

    def test_probe_result_error_field_is_optional(self):
        r = ProbeResult(probe="tls", obs_id=None, signals={}, error="handshake failed")
        assert r.error == "handshake failed"


class TestAggregatorConstruction:
    def test_aggregator_stores_asset_and_target(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42, intensity="high")
        assert agg.asset_id == 501
        assert agg.target_id == 42
        assert agg.intensity == "high"

    def test_aggregator_intensity_defaults_to_low(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42)
        assert agg.intensity == "low"
