"""Tests for the Prometheus metrics module."""

import pytest


def test_metrics_module_imports():
    """All metric objects and the response helper should be importable."""
    from orchestrator.metrics import (
        metrics_response,
        targets_created,
        vulns_found,
        scans_triggered,
        bounties_submitted,
        active_workers,
        queue_depth,
        connected_sse_clients,
        api_latency,
    )
    assert callable(metrics_response)


def test_metrics_endpoint_returns_response():
    """The metrics_response helper should return a FastAPI Response with Prometheus text."""
    from orchestrator.metrics import metrics_response, targets_created

    targets_created.inc()
    resp = metrics_response()
    body = resp.body.decode() if hasattr(resp.body, "decode") else str(resp.body)
    assert "webbh_targets_created_total" in body
    assert resp.media_type == "text/plain; version=0.0.4; charset=utf-8"


def test_counter_labels_severity():
    """Labelled counters should appear with their label values in the output."""
    from orchestrator.metrics import vulns_found
    from prometheus_client import generate_latest

    vulns_found.labels(severity="high", worker_type="input_validation").inc()
    output = generate_latest().decode()
    assert 'severity="high"' in output


def test_counter_labels_scan_type():
    """scans_triggered counter should accept trigger_type labels."""
    from orchestrator.metrics import scans_triggered
    from prometheus_client import generate_latest

    scans_triggered.labels(trigger_type="rescan").inc()
    output = generate_latest().decode()
    assert 'trigger_type="rescan"' in output


def test_gauge_sse_clients():
    """connected_sse_clients gauge should track inc/dec correctly."""
    from orchestrator.metrics import connected_sse_clients

    # Reset to a known state
    connected_sse_clients._value.set(0)
    connected_sse_clients.inc()
    connected_sse_clients.inc()
    assert connected_sse_clients._value.get() == 2.0
    connected_sse_clients.dec()
    assert connected_sse_clients._value.get() == 1.0
    # Clean up
    connected_sse_clients._value.set(0)


def test_histogram_api_latency():
    """api_latency histogram should record observations with labels."""
    from orchestrator.metrics import api_latency
    from prometheus_client import generate_latest

    api_latency.labels(method="GET", endpoint="/api/v1/targets").observe(0.042)
    output = generate_latest().decode()
    assert "webbh_api_latency_seconds" in output
    assert 'method="GET"' in output


def test_bounties_submitted_counter():
    """bounties_submitted counter should accept platform labels."""
    from orchestrator.metrics import bounties_submitted
    from prometheus_client import generate_latest

    bounties_submitted.labels(platform="hackerone").inc()
    output = generate_latest().decode()
    assert 'platform="hackerone"' in output
    assert "webbh_bounties_submitted_total" in output
