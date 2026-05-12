# tests/test_info_gathering_base_tool.py
"""Regression tests for InfoGatheringTool base helpers."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from workers.info_gathering.base_tool import InfoGatheringTool


class _Dummy(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> None:
        ...


class TestSaveObservation:
    @pytest.mark.anyio
    async def test_save_observation_accepts_asset_id_keyword(self):
        """Locks the kwarg contract: save_observation(asset_id=..., tech_stack=..., status_code=..., headers=...)."""
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            sess.add = MagicMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            sess.refresh = AsyncMock(side_effect=lambda obs: setattr(obs, "id", 42))
            obs_id = await tool.save_observation(
                asset_id=501,
                tech_stack={"_probe": "banner", "server": "nginx"},
                status_code=200,
                headers={"Server": "nginx"},
            )
        sess.add.assert_called_once()
        sess.commit.assert_awaited_once()
        sess.refresh.assert_awaited_once()
        assert obs_id == 42
