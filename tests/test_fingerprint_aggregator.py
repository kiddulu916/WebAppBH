# tests/test_fingerprint_aggregator.py
"""Tests for the Stage 2 FingerprintAggregator and ProbeResult dataclass."""
from unittest.mock import AsyncMock, patch

import pytest

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


class TestScoring:
    def test_no_signals_returns_null_slot(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        slot = agg._score_slot("edge", [])
        assert slot == {"vendor": None, "confidence": 0.0, "signals": [], "conflict": False}

    def test_single_signal_below_threshold_is_null_with_partial_signals(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="header_order", obs_id=1, signals={"edge": [
                {"src": "header_order", "value": "Cloudflare", "w": 0.3},
            ]}),
        ]
        slot = agg._score_slot("edge", results)
        assert slot["vendor"] is None
        assert slot["confidence"] == pytest.approx(0.3)
        assert slot["conflict"] is False
        # Below-threshold signals are still preserved for downstream adjudication
        assert any(s["value"] == "Cloudflare" for s in slot["signals"])

    def test_three_signals_sum_above_threshold(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={"edge": [
                {"src": "banner.server", "value": "Cloudflare", "w": 0.6},
            ]}),
            ProbeResult(probe="tls", obs_id=2, signals={"edge": [
                {"src": "tls.cert_issuer", "value": "Cloudflare", "w": 0.5},
            ]}),
            ProbeResult(probe="waf", obs_id=3, signals={"edge": [
                {"src": "waf_passive", "value": "Cloudflare", "w": 0.4},
            ]}),
        ]
        slot = agg._score_slot("edge", results)
        # Cloudflare: 0.6 + 0.5 + 0.4 = 1.5 → clamped to 1.0
        assert slot["vendor"] == "Cloudflare"
        assert slot["confidence"] == 1.0
        assert slot["conflict"] is False

    def test_confidence_clamped_to_one(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="a", obs_id=1, signals={"origin_server": [
                {"src": "banner.server", "value": "nginx", "w": 0.6},
                {"src": "error_page_signature", "value": "nginx", "w": 0.7},
                {"src": "app_fingerprint", "value": "nginx", "w": 0.5},
            ]}),
        ]
        slot = agg._score_slot("origin_server", results)
        assert slot["vendor"] == "nginx"
        assert slot["confidence"] == 1.0

    def test_conflict_flag_when_two_vendors_tie_above_threshold(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={"origin_server": [
                {"src": "banner.server", "value": "nginx", "w": 0.6},
            ]}),
            ProbeResult(probe="error_page", obs_id=2, signals={"origin_server": [
                {"src": "error_page_signature", "value": "Apache", "w": 0.7},
            ]}),
        ]
        slot = agg._score_slot("origin_server", results)
        assert slot["conflict"] is True
        # Top vendor is Apache (0.7 > 0.6)
        assert slot["vendor"] == "Apache"
        assert slot["confidence"] == pytest.approx(0.7)
        assert "candidates" in slot
        assert "signals" not in slot
        vendors_in_candidates = [c["vendor"] for c in slot["candidates"]]
        # Ordered by descending score
        assert vendors_in_candidates == ["Apache", "nginx"]
        for cand in slot["candidates"]:
            assert "confidence" in cand and "signals" in cand

    def test_errored_probe_is_excluded(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="banner", obs_id=None, signals={"origin_server": [
                {"src": "banner.server", "value": "nginx", "w": 0.6},
            ]}, error="connection refused"),
            # Even a strong below-threshold companion from a different probe should still
            # see the errored one's signals discarded.
            ProbeResult(probe="error_page", obs_id=2, signals={"origin_server": [
                {"src": "error_page_signature", "value": "Apache", "w": 0.3},
            ]}),
        ]
        slot = agg._score_slot("origin_server", results)
        assert slot["vendor"] is None  # Apache below threshold; nginx ignored
        assert slot["confidence"] == pytest.approx(0.3)
        # No nginx signal leaked through
        assert all(s["value"] != "nginx" for s in slot["signals"])


class TestWriteSummary:
    @pytest.mark.anyio
    async def test_write_summary_records_partial_when_probe_errored(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42, intensity="low")
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={"origin_server": [
                {"src": "banner.server", "value": "nginx", "w": 0.6},
            ]}),
            ProbeResult(probe="tls", obs_id=None, signals={}, error="handshake failed"),
        ]
        with patch.object(
            agg, "_save_summary_observation",
            new_callable=AsyncMock, return_value=99,
        ) as save:
            obs_id = await agg.write_summary(results)
        assert obs_id == 99
        payload = save.call_args.args[0]
        assert payload["_probe"] == "summary"
        assert payload["intensity"] == "low"
        assert payload["partial"] is True
        assert payload["fingerprint"]["origin_server"]["vendor"] == "nginx"
        assert payload["raw_probe_obs_ids"] == [1]

    @pytest.mark.anyio
    async def test_write_summary_partial_false_when_all_probes_ok(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42)
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={}),
            ProbeResult(probe="tls", obs_id=2, signals={}),
        ]
        with patch.object(
            agg, "_save_summary_observation",
            new_callable=AsyncMock, return_value=100,
        ) as save:
            await agg.write_summary(results)
        payload = save.call_args.args[0]
        assert payload["partial"] is False
        assert payload["raw_probe_obs_ids"] == [1, 2]

    @pytest.mark.anyio
    async def test_write_summary_merges_tls_summary_from_tls_probe(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42)
        tls_data = {"ja3s": "abcd", "alpn": ["h2"], "cert_issuer": "Cloudflare Inc"}
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={}),
            ProbeResult(probe="tls", obs_id=2, signals={"tls_summary": tls_data}),
        ]
        with patch.object(
            agg, "_save_summary_observation",
            new_callable=AsyncMock, return_value=101,
        ) as save:
            await agg.write_summary(results)
        payload = save.call_args.args[0]
        assert payload["fingerprint"]["tls"] == tls_data

    @pytest.mark.anyio
    async def test_write_summary_skips_tls_from_errored_tls_probe(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42)
        results = [
            ProbeResult(probe="tls", obs_id=None, signals={"tls_summary": {"ja3s": "x"}},
                        error="handshake"),
        ]
        with patch.object(
            agg, "_save_summary_observation",
            new_callable=AsyncMock, return_value=102,
        ) as save:
            await agg.write_summary(results)
        payload = save.call_args.args[0]
        assert payload["fingerprint"]["tls"] == {}

    @pytest.mark.anyio
    async def test_write_summary_covers_every_slot(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42)
        with patch.object(
            agg, "_save_summary_observation",
            new_callable=AsyncMock, return_value=103,
        ) as save:
            await agg.write_summary([])
        payload = save.call_args.args[0]
        for slot in SLOTS:
            assert slot in payload["fingerprint"]
