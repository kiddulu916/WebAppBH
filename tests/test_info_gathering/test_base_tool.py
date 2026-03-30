# tests/test_info_gathering/test_base_tool.py
import pytest
from abc import ABC

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    from workers.info_gathering.base_tool import InfoGatheringTool

    assert issubclass(InfoGatheringTool, ABC)

    with pytest.raises(TypeError):
        InfoGatheringTool()  # Cannot instantiate abstract class


def test_base_tool_has_worker_type():
    from workers.info_gathering.base_tool import InfoGatheringTool

    assert InfoGatheringTool.worker_type == "info_gathering"