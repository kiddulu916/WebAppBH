"""Tests for cloud_worker tools."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_cloud_worker_concurrency_weight_classes():
    from workers.cloud_worker.concurrency import WeightClass

    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.LIGHT.value == "light"


def test_cloud_worker_concurrency_get_semaphore():
    from workers.cloud_worker.concurrency import WeightClass, get_semaphore

    sem = get_semaphore(WeightClass.HEAVY)
    assert sem is not None


def test_cloud_test_tool_is_abstract():
    import inspect
    from workers.cloud_worker.base_tool import CloudTestTool

    assert inspect.isabstract(CloudTestTool)


def test_cloud_test_tool_provider_detection():
    from workers.cloud_worker.base_tool import detect_provider

    assert detect_provider("https://mybucket.s3.amazonaws.com") == "aws"
    assert detect_provider("https://myaccount.blob.core.windows.net/container") == "azure"
    assert detect_provider("https://storage.googleapis.com/mybucket") == "gcp"
    assert detect_provider("https://myapp.appspot.com") == "gcp"
    assert detect_provider("https://myapp.firebaseio.com") == "gcp"
    assert detect_provider("https://example.com") is None


CLOUD_URL_PATTERNS_FOR_TEST = [
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "storage.googleapis.com",
    "appspot.com",
    "firebaseio.com",
]


def test_cloud_url_patterns_exported():
    from workers.cloud_worker.base_tool import CLOUD_URL_PATTERNS

    for pattern in CLOUD_URL_PATTERNS_FOR_TEST:
        assert any(pattern in p for p in CLOUD_URL_PATTERNS)
