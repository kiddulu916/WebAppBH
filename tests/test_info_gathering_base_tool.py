# tests/test_info_gathering_base_tool.py
"""Regression tests for InfoGatheringTool base helpers."""
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.base_tool import InfoGatheringTool


class _Dummy(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs):
        return {"found": 0}


class TestSaveObservation:
    @pytest.mark.anyio
    async def test_save_observation_takes_asset_id_not_target_id(self):
        """save_observation must accept asset_id as first positional arg."""
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            sess.refresh = AsyncMock(side_effect=lambda obs: setattr(obs, "id", 42))
            obs_id = await tool.save_observation(
                asset_id=501,
                tech_stack={"_probe": "banner", "server": "nginx"},
                status_code=200,
                headers={"Server": "nginx"},
            )
        assert obs_id == 42
