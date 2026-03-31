# tests/test_error_handling/test_base_tool.py
import pytest
from abc import ABC

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    from workers.error_handling.base_tool import ErrorHandlingTool

    assert issubclass(ErrorHandlingTool, ABC)

    with pytest.raises(TypeError):
        ErrorHandlingTool()  # Cannot instantiate abstract class


def test_base_tool_has_worker_type():
    from workers.error_handling.base_tool import ErrorHandlingTool

    assert ErrorHandlingTool.worker_type == "error_handling"