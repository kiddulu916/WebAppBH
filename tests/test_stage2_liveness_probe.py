# tests/test_stage2_liveness_probe.py
"""Tests for the Stage 2 LivenessProbe."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.tools.liveness_probe import HTTP_PORTS, LivenessProbe


class TestLivenessProbe:
    def test_http_ports_set(self):
        assert HTTP_PORTS == [80, 443, 8000, 8008, 8080, 8443, 4443, 8888]

    @pytest.mark.anyio
    async def test_writes_one_location_per_alive_port(self, tmp_path):
        probe = LivenessProbe()
        httpx_out = "\n".join([
            '{"url":"https://api.acme.com:443","port":443,"status_code":200,"tech":["nginx"]}',
            '{"url":"http://api.acme.com:80","port":80,"status_code":301,"tech":[]}',
        ])
        fake_tmp = MagicMock()
        fake_tmp.name = str(tmp_path / "hosts.txt")
        fake_tmp.__enter__ = MagicMock(return_value=fake_tmp)
        fake_tmp.__exit__ = MagicMock(return_value=False)
        with patch("workers.info_gathering.tools.liveness_probe.tempfile.NamedTemporaryFile",
                   return_value=fake_tmp), \
             patch("workers.info_gathering.tools.liveness_probe.os.path.exists",
                   return_value=False), \
             patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=httpx_out), \
             patch.object(probe, "save_location",
                          new_callable=AsyncMock, return_value=1) as loc, \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=10) as obs:
            result = await probe.execute(
                target_id=1, asset_id=501, host="api.acme.com", intensity="low",
            )
        assert loc.call_count == 2
        ports_written = {c.kwargs["port"] for c in loc.call_args_list}
        assert ports_written == {443, 80}
        services = {c.kwargs["port"]: c.kwargs["service"] for c in loc.call_args_list}
        assert services[443] == "https"
        assert services[80] == "http"
        assert obs.call_count == 1
        assert isinstance(result, ProbeResult)
        assert result.probe == "liveness"
        assert result.obs_id == 10
        assert sorted(result.signals["alive_ports"]) == [80, 443]

    @pytest.mark.anyio
    async def test_returns_error_result_on_subprocess_failure(self, tmp_path):
        probe = LivenessProbe()
        fake_tmp = MagicMock()
        fake_tmp.name = str(tmp_path / "hosts.txt")
        fake_tmp.__enter__ = MagicMock(return_value=fake_tmp)
        fake_tmp.__exit__ = MagicMock(return_value=False)
        with patch("workers.info_gathering.tools.liveness_probe.tempfile.NamedTemporaryFile",
                   return_value=fake_tmp), \
             patch("workers.info_gathering.tools.liveness_probe.os.path.exists",
                   return_value=False), \
             patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, side_effect=RuntimeError("missing binary")):
            result = await probe.execute(
                target_id=1, asset_id=501, host="api.acme.com", intensity="low",
            )
        assert result.probe == "liveness"
        assert result.obs_id is None
        assert result.error == "missing binary"

    @pytest.mark.anyio
    async def test_missing_kwargs_returns_error_result(self):
        probe = LivenessProbe()
        result = await probe.execute(target_id=1, asset_id=None, host="a.com")
        assert result.error == "missing host or asset_id"

    @pytest.mark.anyio
    async def test_skips_lines_with_invalid_json_or_port(self, tmp_path):
        probe = LivenessProbe()
        httpx_out = "\n".join([
            "not json at all",
            '{"url":"https://api.acme.com:443","port":443,"status_code":200,"tech":[]}',
            '{"url":"no port here","status_code":200}',
            '{"url":"x","port":"abc","status_code":200}',
        ])
        fake_tmp = MagicMock()
        fake_tmp.name = str(tmp_path / "hosts.txt")
        fake_tmp.__enter__ = MagicMock(return_value=fake_tmp)
        fake_tmp.__exit__ = MagicMock(return_value=False)
        with patch("workers.info_gathering.tools.liveness_probe.tempfile.NamedTemporaryFile",
                   return_value=fake_tmp), \
             patch("workers.info_gathering.tools.liveness_probe.os.path.exists",
                   return_value=False), \
             patch.object(probe, "run_subprocess",
                          new_callable=AsyncMock, return_value=httpx_out), \
             patch.object(probe, "save_location",
                          new_callable=AsyncMock, return_value=1) as loc, \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=10):
            result = await probe.execute(
                target_id=1, asset_id=501, host="api.acme.com", intensity="low",
            )
        # Only the one well-formed line writes a Location.
        assert loc.call_count == 1
        assert result.signals["alive_ports"] == [443]
