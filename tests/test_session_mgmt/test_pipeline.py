"""Tests for session management pipeline module."""
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.session_mgmt.pipeline import STAGES

    assert len(STAGES) == 9
    expected_stages = [
        "session_scheme", "cookie_attributes", "session_fixation",
        "exposed_variables", "csrf", "logout_functionality",
        "session_timeout", "session_puzzling", "session_hijacking"
    ]
    for i, stage in enumerate(STAGES):
        assert stage.name == expected_stages[i]


def test_each_stage_has_tools():
    from workers.session_mgmt.pipeline import STAGES

    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_session_tool_subclasses():
    from workers.session_mgmt.pipeline import STAGES
    from workers.session_mgmt.base_tool import SessionMgmtTool

    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, SessionMgmtTool), f"{tool_cls} is not a SessionMgmtTool"


def test_stage_index_matches_stages():
    from workers.session_mgmt.pipeline import STAGES, STAGE_INDEX

    assert len(STAGE_INDEX) == len(STAGES)
    for stage in STAGES:
        assert stage.name in STAGE_INDEX


def test_pipeline_filters_stages_with_playbook():
    from workers.session_mgmt.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test")
    playbook = {
        "workers": [
            {
                "name": "session_mgmt",
                "stages": [
                    {"name": "session_scheme", "enabled": True},
                    {"name": "cookie_attributes", "enabled": True},
                    {"name": "session_fixation", "enabled": True},
                    {"name": "exposed_variables", "enabled": False},
                    {"name": "csrf", "enabled": True},
                    {"name": "logout_functionality", "enabled": True},
                    {"name": "session_timeout", "enabled": True},
                    {"name": "session_puzzling", "enabled": True},
                    {"name": "session_hijacking", "enabled": True},
                ],
            }
        ]
    }
    filtered = pipeline._filter_stages(playbook)
    assert len(filtered) == 8
    stage_names = [s.name for s in filtered]
    assert "exposed_variables" not in stage_names


def test_pipeline_returns_all_stages_without_playbook():
    from workers.session_mgmt.pipeline import Pipeline, STAGES

    pipeline = Pipeline(target_id=1, container_name="test")
    filtered = pipeline._filter_stages(None)
    assert len(filtered) == len(STAGES)


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.session_mgmt.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_resume_stage", return_value="cookie_attributes"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.session_mgmt.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 7
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        expected_remaining = [
                            "session_fixation", "exposed_variables", "csrf",
                            "logout_functionality", "session_timeout",
                            "session_puzzling", "session_hijacking"
                        ]
                        assert called_stages == expected_remaining


@pytest.mark.anyio
async def test_run_pipeline_from_start():
    from workers.session_mgmt.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_resume_stage", return_value=None):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.session_mgmt.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 9
