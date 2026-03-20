"""Tests for network_worker pipeline."""

import os

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_pipeline_has_four_stages():
    from workers.network_worker.pipeline import STAGES

    assert len(STAGES) == 4


def test_pipeline_stage_names():
    from workers.network_worker.pipeline import STAGES

    names = [s.name for s in STAGES]
    assert names == [
        "port_discovery", "service_scan", "credential_test", "exploit_verify",
    ]


def test_pipeline_stage_index():
    from workers.network_worker.pipeline import STAGE_INDEX

    assert STAGE_INDEX["port_discovery"] == 0
    assert STAGE_INDEX["service_scan"] == 1
    assert STAGE_INDEX["credential_test"] == 2
    assert STAGE_INDEX["exploit_verify"] == 3


def test_pipeline_aggregate_results():
    from workers.network_worker.pipeline import Pipeline

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


def test_tools_init_exports():
    from workers.network_worker.tools import (
        NaabuTool,
        NmapTool,
        BannerGrabTool,
        MedusaTool,
        LdapInjectionTool,
        MsfCheckTool,
    )
    assert NaabuTool is not None
    assert NmapTool is not None
    assert BannerGrabTool is not None
    assert MedusaTool is not None
    assert LdapInjectionTool is not None
    assert MsfCheckTool is not None
