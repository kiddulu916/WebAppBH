"""Unit tests for FrameworkFingerprintAggregator (WSTG 4.1.8)."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _make_probe(probe: str, signals: dict, obs_id: int = 1, error=None) -> ProbeResult:
    return ProbeResult(probe=probe, obs_id=obs_id, signals=signals, error=error)


def test_wstg_score_slot_single_vendor_above_threshold():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [
        _make_probe("wappalyzer", {"cms": [{"src": "wappalyzer", "value": "WordPress", "w": 0.6}]}),
        _make_probe("meta_generator", {"cms": [{"src": "meta_generator", "value": "WordPress", "w": 0.8}]}),
    ]
    scored = agg._score_slot("cms", results)
    assert scored["vendor"] == "WordPress"
    assert scored["confidence"] >= 0.5
    assert scored["conflict"] is False


def test_wstg_score_slot_below_threshold_returns_null_vendor():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [_make_probe("cookie_framework", {"cms": [{"src": "cookie_framework", "value": "WordPress", "w": 0.3}]})]
    scored = agg._score_slot("cms", results)
    assert scored["vendor"] is None


def test_wstg_score_slot_conflict_two_vendors():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [
        _make_probe("wappalyzer",       {"cms": [{"src": "wappalyzer",    "value": "WordPress", "w": 0.6}]}),
        _make_probe("meta_generator",   {"cms": [{"src": "meta_generator","value": "Joomla",    "w": 0.8}]}),
    ]
    scored = agg._score_slot("cms", results)
    assert scored["conflict"] is True
    vendors = [c["vendor"] for c in scored["candidates"]]
    assert "WordPress" in vendors
    assert "Joomla" in vendors


def test_wstg_score_slot_errored_probe_ignored():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    results = [
        _make_probe("wappalyzer", {"cms": [{"src": "wappalyzer", "value": "WordPress", "w": 0.6}]}, error="timeout"),
        _make_probe("meta_generator", {"cms": [{"src": "meta_generator", "value": "WordPress", "w": 0.8}]}),
    ]
    scored = agg._score_slot("cms", results)
    # Only meta_generator (w=0.8) contributes; wappalyzer errored
    assert scored["confidence"] <= 0.8


@pytest.mark.asyncio
async def test_wstg_corroborated_version_identification():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    fingerprint = {
        "cms": {"vendor": "WordPress", "confidence": 0.9, "conflict": False,
                "signals": [
                    {"src": "meta_generator",   "value": "WordPress", "w": 0.8},
                    {"src": "header_framework",  "value": "WordPress", "w": 0.5},
                ]},
        "framework": {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
        "language":  {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
    }
    raw = {
        "meta_generator":   {"obs_id": 10, "version_signals": [{"vendor": "WordPress", "version": "6.4.2", "slot": "cms"}], "all_vendors": ["WordPress"]},
        "header_framework": {"obs_id": 11, "version_signals": [], "all_vendors": ["WordPress"]},
    }
    saved_vulns = []
    async def _fake_save_vuln(*, title, severity, evidence):
        saved_vulns.append({"title": title, "severity": severity, "evidence": evidence})
        return len(saved_vulns)
    with patch.object(agg, "_save_vuln", side_effect=_fake_save_vuln):
        vuln_ids = await agg.emit_disclosures(fingerprint, raw)

    assert len(vuln_ids) >= 1
    titles = [v["title"] for v in saved_vulns]
    assert any("Corroborated" in t and "WordPress" in t for t in titles)
    # Individual INFO vulns for WordPress should NOT be emitted when corroborated
    assert not any("disclosed via" in t.lower() and "WordPress" in t for t in titles)


@pytest.mark.asyncio
async def test_wstg_admin_path_vuln_emitted():
    from workers.info_gathering.framework_fingerprint_aggregator import FrameworkFingerprintAggregator
    agg = FrameworkFingerprintAggregator(asset_id=1, target_id=1)
    fingerprint = {
        "cms": {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
        "framework": {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
        "language":  {"vendor": None, "confidence": 0.0, "conflict": False, "signals": []},
    }
    raw = {"framework_files": {"obs_id": 30, "admin_paths": ["/wp-login.php"], "info_file_paths": []}}
    saved = []
    async def _fake(*, title, severity, evidence):
        saved.append({"title": title, "severity": severity})
        return len(saved)
    with patch.object(agg, "_save_vuln", side_effect=_fake):
        await agg.emit_disclosures(fingerprint, raw)
    assert any("/wp-login.php" in v["title"] for v in saved)
    assert any(v["severity"] == "LOW" for v in saved)
