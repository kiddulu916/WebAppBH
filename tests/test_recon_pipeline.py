import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.recon_core.pipeline import STAGES
    assert len(STAGES) == 6
    assert STAGES[0].name == "passive_discovery"
    assert STAGES[1].name == "active_discovery"
    assert STAGES[2].name == "liveness_dns"
    assert STAGES[3].name == "fingerprinting"
    assert STAGES[4].name == "port_mapping"
    assert STAGES[5].name == "deep_recon"


def test_each_stage_has_tools():
    from workers.recon_core.pipeline import STAGES
    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_recon_tool_subclasses():
    from workers.recon_core.pipeline import STAGES
    from workers.recon_core.base_tool import ReconTool
    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, ReconTool), f"{tool_cls} is not a ReconTool"


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.recon_core.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value="active_discovery"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "in_scope": 0, "new": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.recon_core.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 4
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        assert called_stages == ["liveness_dns", "fingerprinting", "port_mapping", "deep_recon"]
