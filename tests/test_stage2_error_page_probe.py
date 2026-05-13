# tests/test_stage2_error_page_probe.py
"""Tests for the Stage 2 ErrorPageProbe."""
from unittest.mock import AsyncMock, patch

import pytest

from tests._stage2_helpers import fake_session as _fake_session_factory
from workers.info_gathering.tools.error_page_probe import ErrorPageProbe


def _fake_session(body: str, status: int = 404, exception=None):
    return _fake_session_factory(body=body, status=status, exception=exception)


class TestErrorPageProbe:
    @pytest.mark.anyio
    async def test_matches_nginx_default_404(self):
        probe = ErrorPageProbe()
        body = ('<html><head><title>404 Not Found</title></head>'
                '<body><center><h1>404 Not Found</h1></center>'
                '<hr><center>nginx/1.25.0</center></body></html>')
        session = _fake_session(body)
        with patch("workers.info_gathering.tools.error_page_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=5) as obs:
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        body_tech = obs.call_args.kwargs["tech_stack"]
        assert body_tech["signature_match"] == "nginx-default-404"
        assert "body_sha256" in body_tech and len(body_tech["body_sha256"]) == 64
        assert any(s["src"] == "error_page_signature" and s["value"] == "nginx"
                   for s in result.signals["origin_server"])

    @pytest.mark.anyio
    async def test_express_signature_routed_to_framework_slot(self):
        probe = ErrorPageProbe()
        session = _fake_session("Cannot GET /random", status=404)
        with patch("workers.info_gathering.tools.error_page_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=6):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert any(s["value"] == "Express" for s in result.signals["framework"])
        assert result.signals["origin_server"] == []

    @pytest.mark.anyio
    async def test_cloudflare_signature_routed_to_edge_slot(self):
        probe = ErrorPageProbe()
        session = _fake_session("Error 1020 ray ID: abc123", status=403)
        with patch("workers.info_gathering.tools.error_page_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=7):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert any(s["value"] == "Cloudflare" for s in result.signals["edge"])

    @pytest.mark.anyio
    async def test_no_signature_match_emits_no_signals(self):
        probe = ErrorPageProbe()
        session = _fake_session("Custom 404 page, nothing recognizable", status=404)
        with patch("workers.info_gathering.tools.error_page_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=8) as obs:
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert obs.call_args.kwargs["tech_stack"]["signature_match"] is None
        assert result.signals["origin_server"] == []
        assert result.signals["framework"] == []
        assert result.signals["edge"] == []

    @pytest.mark.anyio
    async def test_tomcat_default_page_routes_to_tomcat_not_apache(self):
        """Regression: ``Apache Tomcat`` body must match Tomcat, not Apache."""
        probe = ErrorPageProbe()
        body = ('<html><head><title>Apache Tomcat/9.0.50 - Error report</title></head>'
                '<body><h1>HTTP Status 404</h1></body></html>')
        session = _fake_session(body, status=404)
        with patch("workers.info_gathering.tools.error_page_probe.aiohttp.ClientSession",
                   return_value=session), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=99) as obs:
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert obs.call_args.kwargs["tech_stack"]["signature_match"] == "tomcat-default-404"
        assert any(s["value"] == "Tomcat" for s in result.signals["origin_server"])
        assert all(s["value"] != "Apache" for s in result.signals["origin_server"])

    @pytest.mark.anyio
    async def test_connection_failure_returns_error_result(self):
        probe = ErrorPageProbe()
        session = _fake_session("", exception=ConnectionError("refused"))
        with patch("workers.info_gathering.tools.error_page_probe.aiohttp.ClientSession",
                   return_value=session):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error is not None

    @pytest.mark.anyio
    async def test_missing_kwargs_returns_error_result(self):
        probe = ErrorPageProbe()
        result = await probe.execute(target_id=1, asset_id=None, host="a.com")
        assert result.error == "missing host or asset_id"
