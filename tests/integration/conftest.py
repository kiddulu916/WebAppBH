"""Integration test configuration."""
import pytest


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --integration flag is passed."""
    if not config.getoption("--integration", default=False):
        skip_integration = pytest.mark.skip(reason="need --integration flag to run")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


def pytest_addoption(parser):
    parser.addoption(
        "--integration", action="store_true", default=False,
        help="run integration tests",
    )
