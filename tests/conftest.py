import pytest

pytest_plugins = ["tests.conftest_orchestrator"]


@pytest.fixture
def anyio_backend():
    return "asyncio"
