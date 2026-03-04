import asyncio
from unittest.mock import MagicMock

import pytest


def test_recon_tool_is_abstract():
    from workers.recon_core.base_tool import ReconTool
    with pytest.raises(TypeError):
        ReconTool()


def test_subclass_must_implement_build_command_and_parse_output():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class Incomplete(ReconTool):
        name = "incomplete"
        weight_class = WeightClass.LIGHT

    with pytest.raises(TypeError):
        Incomplete()


def test_concrete_subclass_can_instantiate():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class FakeTool(ReconTool):
        name = "fake"
        weight_class = WeightClass.LIGHT

        def build_command(self, target, headers=None):
            return ["echo", "hello"]

        def parse_output(self, stdout):
            return stdout.strip().splitlines()

    tool = FakeTool()
    assert tool.name == "fake"
    assert tool.weight_class == WeightClass.LIGHT


def test_build_command_returns_list():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class FakeTool(ReconTool):
        name = "fake"
        weight_class = WeightClass.LIGHT

        def build_command(self, target, headers=None):
            return ["echo", target.base_domain]

        def parse_output(self, stdout):
            return [stdout.strip()]

    tool = FakeTool()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert cmd == ["echo", "example.com"]


@pytest.mark.anyio
async def test_run_subprocess_captures_stdout():
    from workers.recon_core.base_tool import ReconTool
    from workers.recon_core.concurrency import WeightClass

    class EchoTool(ReconTool):
        name = "echo_tool"
        weight_class = WeightClass.LIGHT

        def build_command(self, target, headers=None):
            return ["echo", "sub.example.com"]

        def parse_output(self, stdout):
            return [line for line in stdout.strip().splitlines() if line]

    tool = EchoTool()
    stdout = await tool.run_subprocess(["echo", "sub.example.com"], timeout=5)
    assert "sub.example.com" in stdout
