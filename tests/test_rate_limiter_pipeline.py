"""Tests for rate limiter integration into the info_gathering pipeline."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestBaseToolRateLimiting:
    """Test that InfoGatheringTool acquires rate limits before requests."""

    @pytest.mark.anyio
    async def test_acquire_rate_limit_calls_limiter(self):
        """acquire_rate_limit delegates to rate_limiter.acquire()."""
        from workers.info_gathering.base_tool import InfoGatheringTool

        class DummyTool(InfoGatheringTool):
            async def execute(self, target_id, **kwargs):
                return {"found": 0}

        tool = DummyTool()
        mock_limiter = AsyncMock()
        mock_limiter.acquire = AsyncMock()

        await tool.acquire_rate_limit(mock_limiter)
        mock_limiter.acquire.assert_called_once()

    @pytest.mark.anyio
    async def test_acquire_rate_limit_noop_when_none(self):
        """acquire_rate_limit is a no-op when rate_limiter is None."""
        from workers.info_gathering.base_tool import InfoGatheringTool

        class DummyTool(InfoGatheringTool):
            async def execute(self, target_id, **kwargs):
                return {"found": 0}

        tool = DummyTool()
        # Should not raise
        await tool.acquire_rate_limit(None)

    @pytest.mark.anyio
    async def test_run_subprocess_acquires_rate_limit(self):
        """run_subprocess calls acquire before executing the command."""
        from workers.info_gathering.base_tool import InfoGatheringTool

        class DummyTool(InfoGatheringTool):
            async def execute(self, target_id, **kwargs):
                return {"found": 0}

        tool = DummyTool()
        mock_limiter = AsyncMock()
        mock_limiter.acquire = AsyncMock()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"output", b""))
            mock_exec.return_value = mock_proc

            result = await tool.run_subprocess(
                ["echo", "test"], rate_limiter=mock_limiter,
            )
            mock_limiter.acquire.assert_called_once()
            assert result == "output"

    @pytest.mark.anyio
    async def test_run_subprocess_works_without_rate_limiter(self):
        """run_subprocess works normally when no rate_limiter is provided."""
        from workers.info_gathering.base_tool import InfoGatheringTool

        class DummyTool(InfoGatheringTool):
            async def execute(self, target_id, **kwargs):
                return {"found": 0}

        tool = DummyTool()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"hello", b""))
            mock_exec.return_value = mock_proc

            result = await tool.run_subprocess(["echo", "test"])
            assert result == "hello"


class TestPipelineRateLimiterPassthrough:
    """Test that the Pipeline passes rate_limiter through to tools."""

    @pytest.mark.anyio
    async def test_rate_limiter_passed_to_tool_execute(self):
        """Pipeline._run_stage passes rate_limiter kwarg to tool.execute()."""
        from workers.info_gathering.pipeline import Pipeline, Stage

        mock_tool_cls = MagicMock()
        mock_tool_instance = AsyncMock()
        mock_tool_instance.execute = AsyncMock(return_value={"found": 5})
        mock_tool_cls.return_value = mock_tool_instance

        stage = Stage(name="test_stage", section_id="test", tools=[mock_tool_cls])

        pipeline = Pipeline(target_id=1, container_name="info_gathering")
        mock_limiter = AsyncMock()

        with patch.object(pipeline, '_classify_pending_assets', new_callable=AsyncMock, return_value=0):
            scope_manager = MagicMock()
            scope_manager._in_scope_patterns = []

            await pipeline._run_stage(
                stage, target=None, scope_manager=scope_manager,
                headers=None, rate_limiter=mock_limiter,
            )

            mock_tool_instance.execute.assert_called_once()
            call_kwargs = mock_tool_instance.execute.call_args[1]
            assert call_kwargs["rate_limiter"] is mock_limiter
