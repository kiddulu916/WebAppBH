"""Prometheus metrics for the WebAppBH orchestrator."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response


# Counters
targets_created = Counter(
    "webbh_targets_created_total",
    "Total targets created",
)
vulns_found = Counter(
    "webbh_vulns_found_total",
    "Total vulnerabilities discovered",
    ["severity"],
)
scans_triggered = Counter(
    "webbh_scans_triggered_total",
    "Scans triggered",
    ["trigger_type"],
)
bounties_submitted = Counter(
    "webbh_bounties_submitted_total",
    "Bounty submissions created",
    ["platform"],
)

# Gauges
active_workers = Gauge(
    "webbh_active_workers",
    "Currently running workers",
)
queue_depth = Gauge(
    "webbh_queue_depth",
    "Pending messages per queue",
    ["queue"],
)
connected_sse_clients = Gauge(
    "webbh_sse_clients",
    "Connected SSE clients",
)

# Histograms
api_latency = Histogram(
    "webbh_api_latency_seconds",
    "API request latency",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)


def metrics_response() -> Response:
    """Generate Prometheus metrics response."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
