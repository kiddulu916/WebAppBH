"""Unit tests for InfrastructureMixin.get_testing_user_credentials()."""
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from lib_webbh.infra_mixin import InfrastructureMixin


class _Tool(InfrastructureMixin):
    pass


@pytest.fixture
def tool():
    return _Tool()


@pytest.mark.asyncio
async def test_get_testing_user_credentials_returns_dict(tool):
    creds = {
        "tester": {"username": "t", "password": "p", "auth_type": "form"},
        "testing_user": {"username": "victim", "email": "v@example.com", "password": "vpass"},
    }
    with patch.object(tool, "_load_credentials", return_value=creds):
        result = await tool.get_testing_user_credentials(42)
    assert result == creds["testing_user"]
    assert result["password"] == "vpass"


@pytest.mark.asyncio
async def test_get_testing_user_credentials_returns_none_when_missing(tool):
    with patch.object(tool, "_load_credentials", return_value=None):
        result = await tool.get_testing_user_credentials(99)
    assert result is None


@pytest.mark.asyncio
async def test_get_testing_user_credentials_returns_none_when_key_absent(tool):
    with patch.object(tool, "_load_credentials", return_value={"tester": {"username": "t"}}):
        result = await tool.get_testing_user_credentials(7)
    assert result is None
