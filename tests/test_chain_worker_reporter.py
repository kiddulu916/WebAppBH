# tests/test_chain_worker_reporter.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from datetime import datetime
from workers.chain_worker.tools.chain_reporter import ChainReporter
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainResult, ChainStep


def test_tool_attributes():
    tool = ChainReporter()
    assert tool.name == "chain_reporter"
    assert tool.weight_class == WeightClass.LIGHT


def test_build_description():
    tool = ChainReporter()
    steps = [
        ChainStep(action="ssrf_probe", target="import_url", result="200 OK", timestamp=datetime.now().isoformat()),
        ChainStep(action="imds_query", target="169.254.169.254", result="iam_role_found", timestamp=datetime.now().isoformat()),
    ]
    result = ChainResult(success=True, steps=steps, poc="curl http://target.com/import?url=http://169.254.169.254/", chain_name="ssrf_cloud")
    desc = tool._build_description(result)
    assert "Step 1:" in desc
    assert "Step 2:" in desc
    assert "ssrf_probe" in desc


def test_build_tech_stack_json():
    tool = ChainReporter()
    steps = [
        ChainStep(action="test", target="t", result="ok", timestamp="2026-03-20T14:00:00", screenshot_path="/evidence/step_1.png"),
    ]
    result = ChainResult(success=True, steps=steps, poc="test", chain_name="test_chain")
    tech = tool._build_tech_stack(result, "test_category")
    assert tech["chain_type"] == "test_chain"
    assert tech["chain_category"] == "test_category"
    assert tech["total_steps"] == 1
    assert tech["steps"][0]["screenshot"] == "/evidence/step_1.png"
