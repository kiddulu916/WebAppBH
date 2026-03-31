# tests/test_business_logic/test_base_tool.py
import pytest
from abc import ABC

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    from workers.business_logic.base_tool import BusinessLogicTool

    assert issubclass(BusinessLogicTool, ABC)

    with pytest.raises(TypeError):
        BusinessLogicTool()  # Cannot instantiate abstract class


def test_base_tool_has_worker_type():
    from workers.business_logic.base_tool import BusinessLogicTool

    assert BusinessLogicTool.worker_type == "business_logic"