import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_stages_defined_in_order():
    from workers.input_validation.pipeline import STAGES
    assert len(STAGES) == 19
    assert STAGES[0].name == "reflected_xss"
    assert STAGES[1].name == "stored_xss"
    assert STAGES[2].name == "http_verb_tampering"
    assert STAGES[3].name == "http_param_pollution"
    assert STAGES[4].name == "sql_injection"
    assert STAGES[5].name == "ldap_injection"
    assert STAGES[6].name == "xml_injection"
    assert STAGES[7].name == "ssti"
    assert STAGES[8].name == "xpath_injection"
    assert STAGES[9].name == "imap_smtp_injection"
    assert STAGES[10].name == "code_injection"
    assert STAGES[11].name == "command_injection"
    assert STAGES[12].name == "format_string"
    assert STAGES[13].name == "host_header_injection"
    assert STAGES[14].name == "ssrf"
    assert STAGES[15].name == "file_inclusion"
    assert STAGES[16].name == "buffer_overflow"
    assert STAGES[17].name == "http_smuggling"
    assert STAGES[18].name == "websocket_injection"
    assert STAGES[15].name == "file_inclusion"
    assert STAGES[16].name == "buffer_overflow"
    assert STAGES[17].name == "http_smuggling"
    assert STAGES[18].name == "websocket_injection"


def test_each_stage_has_tools():
    from workers.input_validation.pipeline import STAGES
    for stage in STAGES:
        assert len(stage.tool_classes) > 0, f"Stage {stage.name} has no tools"


def test_stage_tools_are_input_validation_tool_subclasses():
    from workers.input_validation.pipeline import STAGES
    from workers.input_validation.base_tool import InputValidationTool
    for stage in STAGES:
        for tool_cls in stage.tool_classes:
            assert issubclass(tool_cls, InputValidationTool), f"{tool_cls} is not an InputValidationTool"


@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.input_validation.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_resume_stage", return_value="sql_injection"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "vulnerable": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.input_validation.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()
                        await pipeline.run(target, scope_mgr)