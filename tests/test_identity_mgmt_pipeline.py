import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.identity_mgmt.pipeline import STAGES
    assert len(STAGES) == 5
    assert STAGES[0].name == "role_definitions"
    assert STAGES[1].name == "registration_process"
    assert STAGES[2].name == "account_provisioning"
    assert STAGES[3].name == "account_enumeration"
    assert STAGES[4].name == "weak_username_policy"


def test_each_stage_has_tools():
    from workers.identity_mgmt.pipeline import STAGES
    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_identity_tool_subclasses():
    from workers.identity_mgmt.pipeline import STAGES
    from workers.identity_mgmt.base_tool import IdentityMgmtTool
    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, IdentityMgmtTool), f"{tool_cls} is not an IdentityMgmtTool"


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.identity_mgmt.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value="registration_process"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "inserted": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.identity_mgmt.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 3
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        assert called_stages == ["account_provisioning", "account_enumeration", "weak_username_policy"]