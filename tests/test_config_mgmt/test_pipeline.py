"""Tests for config management pipeline module."""
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.config_mgmt.pipeline import STAGES

    assert len(STAGES) == 11
    expected_stages = [
        "network_infrastructure", "platform_configuration", "file_extension_handling",
        "backup_unreferenced_files", "admin_interface_enumeration", "http_methods",
        "hsts_testing", "cross_domain_policy", "file_permissions",
        "subdomain_takeover", "cloud_storage"
    ]
    for i, stage in enumerate(STAGES):
        assert stage.name == expected_stages[i]


def test_each_stage_has_tools():
    from workers.config_mgmt.pipeline import STAGES

    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_config_tool_subclasses():
    from workers.config_mgmt.pipeline import STAGES
    from workers.config_mgmt.base_tool import ConfigMgmtTool

    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, ConfigMgmtTool), f"{tool_cls} is not a ConfigMgmtTool"


def test_stage_index_matches_stages():
    from workers.config_mgmt.pipeline import STAGES, STAGE_INDEX

    assert len(STAGE_INDEX) == len(STAGES)
    for stage in STAGES:
        assert stage.name in STAGE_INDEX


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.config_mgmt.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value="file_extension_handling"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "in_scope": 0, "new": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.config_mgmt.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 8
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        expected_remaining = [
                            "backup_unreferenced_files", "admin_interface_enumeration", "http_methods",
                            "hsts_testing", "cross_domain_policy", "file_permissions",
                            "subdomain_takeover", "cloud_storage"
                        ]
                        assert called_stages == expected_remaining


@pytest.mark.anyio
async def test_run_pipeline_from_start():
    from workers.config_mgmt.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value=None):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "in_scope": 0, "new": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.config_mgmt.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 11
