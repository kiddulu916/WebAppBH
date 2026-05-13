# tests/test_stage2_whatweb_probe.py
"""Tests for the Stage 2 WhatWeb-as-ProbeResult refactor (Task 2.8)."""
import json
from unittest.mock import AsyncMock, patch

import pytest

from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.tools.whatweb import WhatWeb


class TestWhatWebProbeResult:
    @pytest.mark.anyio
    async def test_returns_probe_result_with_origin_and_framework_signals(self):
        probe = WhatWeb()
        ww = json.dumps([{
            "target": "https://a.com",
            "plugins": {"Apache": {"version": ["2.4.49"]}, "PHP": {}},
        }])
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=ww), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=9):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert isinstance(result, ProbeResult)
        assert result.probe == "app_fingerprint"
        assert result.obs_id == 9
        origin = result.signals["origin_server"]
        framework = result.signals["framework"]
        assert any(s["src"] == "app_fingerprint" and s["value"] == "Apache" for s in origin)
        assert any(s["value"] == "PHP" for s in framework)

    @pytest.mark.anyio
    async def test_cloudflare_plugin_routed_to_edge_slot(self):
        probe = WhatWeb()
        ww = json.dumps([{
            "target": "https://a.com",
            "plugins": {"Cloudflare": {}, "nginx": {}},
        }])
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=ww), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=10):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert any(s["value"] == "Cloudflare" for s in result.signals["edge"])
        assert any(s["value"] == "nginx" for s in result.signals["origin_server"])

    @pytest.mark.anyio
    async def test_unknown_plugins_do_not_emit_signals(self):
        probe = WhatWeb()
        ww = json.dumps([{
            "target": "https://a.com",
            "plugins": {"X-NotAKnownPlugin": {}, "Apache": {}},
        }])
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=ww), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=11):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        all_signal_values = {
            s["value"]
            for slot in ("origin_server", "edge", "framework")
            for s in result.signals[slot]
        }
        assert "X-NotAKnownPlugin" not in all_signal_values
        assert "Apache" in all_signal_values

    @pytest.mark.anyio
    async def test_subprocess_failure_returns_error_probe_result(self):
        probe = WhatWeb()
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert isinstance(result, ProbeResult)
        assert result.error == "boom"
        assert result.obs_id is None

    @pytest.mark.anyio
    async def test_invalid_json_returns_error_probe_result(self):
        probe = WhatWeb()
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value="not json"):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error == "invalid json from whatweb"

    @pytest.mark.anyio
    async def test_non_list_returns_error_probe_result(self):
        probe = WhatWeb()
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value='{"not": "a list"}'):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error == "whatweb returned non-list"

    @pytest.mark.anyio
    async def test_empty_list_returns_signalless_probe_result(self):
        probe = WhatWeb()
        with patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value="[]"):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error is None
        assert result.obs_id is None
        assert result.signals == {}
