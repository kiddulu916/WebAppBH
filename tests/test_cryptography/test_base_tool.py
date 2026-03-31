# tests/test_cryptography/test_base_tool.py
import pytest
from abc import ABC

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    from workers.cryptography.base_tool import CryptographyTool

    assert issubclass(CryptographyTool, ABC)

    with pytest.raises(TypeError):
        CryptographyTool()  # Cannot instantiate abstract class


def test_base_tool_has_worker_type():
    from workers.cryptography.base_tool import CryptographyTool

    assert CryptographyTool.worker_type == "cryptography"