import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.authentication.pipeline import STAGES
    assert len(STAGES) == 10
    expected_stages = [
        "credentials_transport", "default_credentials", "lockout_mechanism",
        "auth_bypass", "remember_password", "browser_cache", "weak_password_policy",
        "security_questions", "password_change", "multi_channel_auth"
    ]
    for i, stage in enumerate(STAGES):
        assert stage.name == expected_stages[i]


def test_each_stage_has_tools():
    from workers.authentication.pipeline import STAGES
    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_auth_tool_subclasses():
    from workers.authentication.pipeline import STAGES
    from workers.authentication.base_tool import AuthenticationTool
    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, AuthenticationTool), f"{tool_cls} is not an AuthenticationTool"


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.authentication.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value="lockout_mechanism"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.authentication.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 7
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        expected_remaining = [
                            "auth_bypass", "remember_password", "browser_cache",
                            "weak_password_policy", "security_questions", "password_change", "multi_channel_auth"
                        ]
                        assert called_stages == expected_remaining