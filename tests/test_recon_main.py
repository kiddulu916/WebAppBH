import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


@pytest.mark.anyio
async def test_handle_message_creates_job_state_and_runs_pipeline():
    with patch("workers.recon_core.main.Pipeline") as MockPipeline, \
         patch("workers.recon_core.main.get_session") as mock_get_session:

        mock_pipeline_instance = MagicMock()
        mock_pipeline_instance.run = AsyncMock()
        MockPipeline.return_value = mock_pipeline_instance

        mock_session = AsyncMock()
        mock_target = MagicMock(
            id=1,
            base_domain="example.com",
            target_profile={
                "in_scope_domains": ["*.example.com"],
                "custom_headers": {"X-Bug-Bounty": "true"},
            },
        )
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_target
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.add = MagicMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_get_session.return_value = mock_ctx

        from workers.recon_core.main import handle_message

        await handle_message("msg-001", {"target_id": 1, "action": "full_recon"})

        MockPipeline.assert_called_once()
        mock_pipeline_instance.run.assert_awaited_once()


def test_container_name_from_hostname():
    with patch.dict(os.environ, {"HOSTNAME": "recon-core-abc123"}):
        from workers.recon_core.main import get_container_name
        assert get_container_name() == "recon-core-abc123"
