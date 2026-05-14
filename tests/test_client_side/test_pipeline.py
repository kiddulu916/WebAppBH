"""Tests for client-side pipeline module."""
import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


@pytest.fixture(autouse=True)
def mock_playwright():
    mock_pw_module = MagicMock()
    mock_pw_instance = MagicMock()
    mock_browser = AsyncMock()
    mock_chromium = MagicMock()
    mock_chromium.launch = AsyncMock(return_value=mock_browser)
    mock_pw_instance.chromium = mock_chromium
    mock_pw_module.start = AsyncMock(return_value=mock_pw_instance)

    with patch.dict(sys.modules, {"playwright.async_api": mock_pw_module}):
        with patch("workers.client_side.browser_manager.async_playwright", return_value=mock_pw_module):
            yield


def test_stages_defined_in_order():
    from workers.client_side.pipeline import STAGES

    assert len(STAGES) == 13
    expected_stages = [
        "dom_xss", "clickjacking", "csrf_tokens", "csp_bypass",
        "html5_injection", "web_storage", "client_side_logic",
        "dom_based_injection", "client_side_resource_manipulation",
        "client_side_auth", "xss_client_side", "css_injection",
        "malicious_upload_client"
    ]
    for i, stage in enumerate(STAGES):
        assert stage.name == expected_stages[i]


def test_each_stage_has_tools():
    from workers.client_side.pipeline import STAGES

    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_client_tool_subclasses():
    from workers.client_side.pipeline import STAGES
    from workers.client_side.base_tool import ClientSideTool

    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, ClientSideTool), f"{tool_cls} is not a ClientSideTool"


def test_stage_index_matches_stages():
    from workers.client_side.pipeline import STAGES, STAGE_INDEX

    assert len(STAGE_INDEX) == len(STAGES)
    for stage in STAGES:
        assert stage.name in STAGE_INDEX


def test_pipeline_filters_stages_with_playbook():
    from workers.client_side.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test")
    playbook = {
        "workers": [
            {
                "name": "client_side",
                "stages": [
                    {"name": "dom_xss", "enabled": True},
                    {"name": "clickjacking", "enabled": False},
                    {"name": "csrf_tokens", "enabled": True},
                    {"name": "csp_bypass", "enabled": True},
                    {"name": "html5_injection", "enabled": True},
                    {"name": "web_storage", "enabled": True},
                    {"name": "client_side_logic", "enabled": True},
                    {"name": "dom_based_injection", "enabled": True},
                    {"name": "client_side_resource_manipulation", "enabled": True},
                    {"name": "client_side_auth", "enabled": True},
                    {"name": "xss_client_side", "enabled": True},
                    {"name": "css_injection", "enabled": True},
                    {"name": "malicious_upload_client", "enabled": True},
                ],
            }
        ]
    }
    filtered = pipeline._filter_stages(playbook)
    assert len(filtered) == 12
    stage_names = [s.name for s in filtered]
    assert "clickjacking" not in stage_names


def test_pipeline_returns_all_stages_without_playbook():
    from workers.client_side.pipeline import Pipeline, STAGES

    pipeline = Pipeline(target_id=1, container_name="test")
    filtered = pipeline._filter_stages(None)
    assert len(filtered) == len(STAGES)

    filtered = pipeline._filter_stages({})
    assert len(filtered) == len(STAGES)


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.client_side.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_resume_stage", return_value="csrf_tokens"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.client_side.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 10
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        expected_remaining = [
                            "csp_bypass", "html5_injection", "web_storage",
                            "client_side_logic", "dom_based_injection",
                            "client_side_resource_manipulation", "client_side_auth",
                            "xss_client_side", "css_injection", "malicious_upload_client"
                        ]
                        assert called_stages == expected_remaining


@pytest.mark.anyio
async def test_run_pipeline_from_start():
    from workers.client_side.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_resume_stage", return_value=None):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.client_side.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 13
