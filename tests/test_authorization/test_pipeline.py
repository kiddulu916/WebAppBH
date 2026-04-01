"""Tests for authorization pipeline module."""
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.authorization.pipeline import STAGES

    assert len(STAGES) == 4
    expected_stages = [
        "directory_traversal", "authz_bypass",
        "privilege_escalation", "idor"
    ]
    for i, stage in enumerate(STAGES):
        assert stage.name == expected_stages[i]


def test_each_stage_has_tools():
    from workers.authorization.pipeline import STAGES

    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_authz_tool_subclasses():
    from workers.authorization.pipeline import STAGES
    from workers.authorization.base_tool import AuthorizationTool

    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, AuthorizationTool), f"{tool_cls} is not an AuthorizationTool"


def test_stage_index_matches_stages():
    from workers.authorization.pipeline import STAGES, STAGE_INDEX

    assert len(STAGE_INDEX) == len(STAGES)
    for stage in STAGES:
        assert stage.name in STAGE_INDEX


def test_pipeline_filters_stages_with_playbook():
    from workers.authorization.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test")
    playbook = {
        "stages": [
            {"name": "directory_traversal", "enabled": True},
            {"name": "authz_bypass", "enabled": False},
            {"name": "privilege_escalation", "enabled": True},
            {"name": "idor", "enabled": True},
        ]
    }
    filtered = pipeline._filter_stages(playbook)
    assert len(filtered) == 3
    stage_names = [s.name for s in filtered]
    assert "authz_bypass" not in stage_names


def test_pipeline_returns_all_stages_without_playbook():
    from workers.authorization.pipeline import Pipeline, STAGES

    pipeline = Pipeline(target_id=1, container_name="test")
    filtered = pipeline._filter_stages(None)
    assert len(filtered) == len(STAGES)

    filtered = pipeline._filter_stages({})
    assert len(filtered) == len(STAGES)


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.authorization.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value="authz_bypass"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.authorization.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 2
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        assert called_stages == ["privilege_escalation", "idor"]


@pytest.mark.anyio
async def test_run_pipeline_from_start():
    from workers.authorization.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value=None):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.authorization.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 4
