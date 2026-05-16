"""Tests for WebSocketProber — WSTG-INFO-06."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.websocket_prober import (
    WebSocketProber,
    WS_PATHS,
    _ws_upgrade_headers,
)


class TestWsUpgradeHeaders:
    def test_contains_all_required_ws_fields(self):
        h = _ws_upgrade_headers()
        assert h["Upgrade"] == "websocket"
        assert h["Connection"] == "Upgrade"
        assert h["Sec-WebSocket-Version"] == "13"
        assert "Sec-WebSocket-Key" in h

    def test_key_is_base64_encoded_16_bytes(self):
        import base64
        key = _ws_upgrade_headers()["Sec-WebSocket-Key"]
        decoded = base64.b64decode(key)
        assert len(decoded) == 16

    def test_key_differs_between_calls(self):
        k1 = _ws_upgrade_headers()["Sec-WebSocket-Key"]
        k2 = _ws_upgrade_headers()["Sec-WebSocket-Key"]
        assert k1 != k2


class TestWsPathWordlist:
    def test_contains_core_ws_paths(self):
        for path in ("/ws", "/socket", "/websocket", "/socket.io", "/chat", "/stream"):
            assert path in WS_PATHS

    def test_has_at_least_ten_paths(self):
        assert len(WS_PATHS) >= 10


class TestWebSocketProber:
    @pytest.mark.anyio
    async def test_missing_target_returns_zero(self):
        result = await WebSocketProber().execute(target_id=1)
        assert result == {"found": 0, "rejected": 0}

    @pytest.mark.anyio
    async def test_missing_asset_id_returns_zero(self):
        result = await WebSocketProber().execute(target_id=1, target=MagicMock())
        assert result == {"found": 0, "rejected": 0}

    @pytest.mark.anyio
    async def test_101_response_creates_websocket_asset_and_observation(self):
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_probe(session, url):
            return (101, True) if url == "https://example.com/ws" else (200, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "save_asset", new_callable=AsyncMock, return_value=10) as mock_save, \
             patch.object(prober, "_lookup_asset_id", new_callable=AsyncMock, return_value=10), \
             patch.object(prober, "save_observation", new_callable=AsyncMock, return_value=1) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(target_id=1, target=target, asset_id=5)

        mock_save.assert_any_call(1, "websocket", "https://example.com/ws", "websocket_prober")
        assert result["found"] >= 1
        obs_call = next(
            c for c in mock_obs.call_args_list
            if c.kwargs.get("tech_stack", {}).get("upgrade_accepted")
        )
        assert obs_call.kwargs["tech_stack"]["path"] == "/ws"

    @pytest.mark.anyio
    async def test_403_writes_observation_but_no_asset(self):
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_probe(session, url):
            return (403, False) if url == "https://example.com/ws" else (200, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "save_asset", new_callable=AsyncMock) as mock_save, \
             patch.object(prober, "save_observation", new_callable=AsyncMock, return_value=1) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(target_id=1, target=target, asset_id=5)

        mock_save.assert_not_called()
        assert mock_obs.called
        rejected_call = next(
            c for c in mock_obs.call_args_list
            if c.kwargs.get("tech_stack", {}).get("upgrade_rejected")
        )
        assert rejected_call.kwargs["tech_stack"]["status"] == 403
        assert result["rejected"] >= 1

    @pytest.mark.anyio
    async def test_connection_error_skipped_no_db_writes(self):
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_probe(session, url):
            return (0, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "save_asset", new_callable=AsyncMock) as mock_save, \
             patch.object(prober, "save_observation", new_callable=AsyncMock) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(target_id=1, target=target, asset_id=5)

        mock_save.assert_not_called()
        mock_obs.assert_not_called()
        assert result == {"found": 0, "rejected": 0}

    @pytest.mark.anyio
    async def test_http_fallback_when_https_fails(self):
        """HTTPS connection error falls back to HTTP and saves the http:// asset."""
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "example.com"

        async def fake_probe(session, url):
            if url == "https://example.com/ws":
                return (0, False)  # HTTPS unreachable
            if url == "http://example.com/ws":
                return (101, True)  # HTTP WS handshake accepted
            return (200, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "save_asset", new_callable=AsyncMock, return_value=20) as mock_save, \
             patch.object(prober, "_lookup_asset_id", new_callable=AsyncMock, return_value=20), \
             patch.object(prober, "save_observation", new_callable=AsyncMock, return_value=1) as mock_obs, \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(target_id=1, target=target, asset_id=5)

        mock_save.assert_any_call(1, "websocket", "http://example.com/ws", "websocket_prober")
        assert result["found"] >= 1

    @pytest.mark.anyio
    async def test_out_of_scope_hosts_skipped(self):
        """Hosts excluded by scope_manager are not probed."""
        prober = WebSocketProber()
        target = MagicMock()
        target.base_domain = "evil.com"

        scope_manager = MagicMock()
        probe_calls: list[str] = []

        async def fake_probe(session, url):
            probe_calls.append(url)
            return (200, False)

        prober._probe = fake_probe

        with patch("workers.info_gathering.tools.websocket_prober.get_session") as mock_gs, \
             patch.object(prober, "scope_check", new_callable=AsyncMock, return_value=False), \
             patch("aiohttp.ClientSession") as mock_http_cls:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            mock_http = AsyncMock()
            mock_http_cls.return_value.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await prober.execute(
                target_id=1, target=target, asset_id=5, scope_manager=scope_manager,
            )

        assert probe_calls == []
        assert result == {"found": 0, "rejected": 0}
