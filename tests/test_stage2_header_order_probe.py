# tests/test_stage2_header_order_probe.py
"""Tests for the Stage 2 HeaderOrderProbe."""
from unittest.mock import AsyncMock, patch

import pytest

from workers.info_gathering.tools.header_order_probe import HeaderOrderProbe


class TestHeaderOrderProbe:
    @pytest.mark.anyio
    async def test_records_header_order_and_title_casing(self):
        probe = HeaderOrderProbe()
        canned = (
            "HTTP/1.1 200 OK\r\n"
            "Date: Mon, 11 May 2026 00:00:00 GMT\r\n"
            "Content-Type: text/html\r\n"
            "Server: nginx/1.25.0\r\n"
            "\r\n"
            "body"
        )
        with patch.object(probe, "_raw_get",
                          new_callable=AsyncMock, return_value=canned), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=2) as obs:
            result = await probe.execute(
                target_id=1, asset_id=501, host="api.acme.com", intensity="low",
            )
        body = obs.call_args.kwargs["tech_stack"]
        assert body["order"] == ["Date", "Content-Type", "Server"]
        assert body["casing"] == "Title-Case"
        assert result.probe == "header_order"
        assert result.obs_id == 2

    @pytest.mark.anyio
    async def test_title_case_with_single_letter_parts(self):
        """Regression: headers with single-letter parts (``X-Cache``, ``X-Frame-Options``) must detect Title-Case."""
        probe = HeaderOrderProbe()
        canned = (
            "HTTP/1.1 200 OK\r\n"
            "Date: x\r\n"
            "X-Cache: HIT\r\n"
            "X-Frame-Options: DENY\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
        )
        with patch.object(probe, "_raw_get",
                          new_callable=AsyncMock, return_value=canned), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=99) as obs:
            await probe.execute(target_id=1, asset_id=501, host="x", intensity="low")
        assert obs.call_args.kwargs["tech_stack"]["casing"] == "Title-Case"

    @pytest.mark.anyio
    async def test_detects_lowercase_casing(self):
        probe = HeaderOrderProbe()
        canned = (
            "HTTP/2 200\r\n"
            "date: x\r\n"
            "content-type: y\r\n"
            "\r\n"
        )
        with patch.object(probe, "_raw_get",
                          new_callable=AsyncMock, return_value=canned), \
             patch.object(probe, "save_observation",
                          new_callable=AsyncMock, return_value=3) as obs:
            await probe.execute(target_id=1, asset_id=501, host="x", intensity="low")
        assert obs.call_args.kwargs["tech_stack"]["casing"] == "lowercase"

    @pytest.mark.anyio
    async def test_socket_failure_returns_error_result(self):
        probe = HeaderOrderProbe()
        with patch.object(probe, "_raw_get",
                          new_callable=AsyncMock, side_effect=OSError("connection refused")):
            result = await probe.execute(
                target_id=1, asset_id=501, host="a.com", intensity="low",
            )
        assert result.error == "connection refused"
        assert result.obs_id is None

    @pytest.mark.anyio
    async def test_missing_kwargs_returns_error_result(self):
        probe = HeaderOrderProbe()
        result = await probe.execute(target_id=1, asset_id=None, host="a.com")
        assert result.error == "missing host or asset_id"
