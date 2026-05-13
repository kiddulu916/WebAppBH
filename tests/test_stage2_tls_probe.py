# tests/test_stage2_tls_probe.py
"""Tests for the Stage 2 TLSProbe."""
import json
from unittest.mock import AsyncMock, patch

import pytest

from workers.info_gathering.tools.tls_probe import TLSProbe


class TestTLSProbe:
    @pytest.mark.anyio
    async def test_parses_tlsx_output_and_records_edge_signal_for_cloudflare(self):
        probe = TLSProbe()
        tlsx_out = json.dumps({
            "host": "api.acme.com",
            "ja3s_hash": "abcd1234",
            "tls_version": "tls13",
            "issuer_cn": "Cloudflare Inc ECC CA-3",
            "subject_an": ["*.acme.com"],
            "alpn": ["h2", "http/1.1"],
        })
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=tlsx_out), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=6):
            result = await probe.execute(
                target_id=1, asset_id=501, host="api.acme.com", intensity="low",
            )
        assert result.probe == "tls"
        assert result.obs_id == 6
        assert any(s["value"] == "Cloudflare" and s["src"] == "tls.cert_issuer"
                   for s in result.signals["edge"])
        assert result.signals["tls_summary"]["ja3s"] == "abcd1234"
        assert result.signals["tls_summary"]["alpn"] == ["h2", "http/1.1"]

    @pytest.mark.anyio
    async def test_unknown_issuer_emits_no_edge_signal(self):
        probe = TLSProbe()
        tlsx_out = json.dumps({
            "ja3s_hash": "x", "issuer_cn": "Let's Encrypt Authority X3",
            "subject_an": [], "alpn": [],
        })
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=tlsx_out), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=7):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.signals["edge"] == []
        assert result.signals["tls_summary"]["cert_issuer"] == "Let's Encrypt Authority X3"

    @pytest.mark.anyio
    async def test_subprocess_failure_returns_error_result(self):
        probe = TLSProbe()
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, side_effect=RuntimeError("tlsx missing")):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error == "tlsx missing"

    @pytest.mark.anyio
    async def test_garbage_output_yields_empty_summary(self):
        probe = TLSProbe()
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value="not json\n"), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=8):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.signals["tls_summary"]["ja3s"] is None
        assert result.signals["edge"] == []

    @pytest.mark.anyio
    async def test_missing_kwargs_returns_error_result(self):
        probe = TLSProbe()
        result = await probe.execute(target_id=1, asset_id=None, host="a.com")
        assert result.error == "missing host or asset_id"
