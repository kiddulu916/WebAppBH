# tests/test_cloud_worker_pipeline.py
"""Tests for cloud_worker pipeline."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_pipeline_has_four_stages():
    from workers.cloud_worker.pipeline import STAGES

    assert len(STAGES) == 4


def test_pipeline_stage_names():
    from workers.cloud_worker.pipeline import STAGES

    names = [s.name for s in STAGES]
    assert names == ["discovery", "probing", "deep_scan", "feedback"]


def test_pipeline_stage_index():
    from workers.cloud_worker.pipeline import STAGE_INDEX

    assert STAGE_INDEX["discovery"] == 0
    assert STAGE_INDEX["probing"] == 1
    assert STAGE_INDEX["deep_scan"] == 2
    assert STAGE_INDEX["feedback"] == 3


def test_pipeline_aggregate_results():
    from workers.cloud_worker.pipeline import Pipeline

    p = Pipeline(target_id=1, container_name="test")
    results = [
        {"found": 5, "in_scope": 3, "new": 2},
        {"found": 10, "in_scope": 8, "new": 6},
        ValueError("tool failed"),
    ]
    agg = p._aggregate_results("test_stage", results)
    assert agg["found"] == 15
    assert agg["in_scope"] == 11
    assert agg["new"] == 8
