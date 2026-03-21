"""Built-in campaign playbooks for WebAppBH.

Each playbook defines which pipeline stages are enabled, tool-specific
parameters, and concurrency settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ConcurrencyConfig:
    heavy: int = 2
    light: int = 4


@dataclass
class StageConfig:
    name: str
    enabled: bool = True
    tool_timeout: int = 600  # seconds


@dataclass
class PlaybookConfig:
    name: str
    description: str
    stages: list[StageConfig] = field(default_factory=list)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)

    def to_dict(self) -> dict:
        return asdict(self)


# All 7 recon stages (from workers/recon_core/pipeline.py)
_ALL_RECON_STAGES = [
    "passive_discovery",
    "active_discovery",
    "liveness_dns",
    "subdomain_takeover",
    "fingerprinting",
    "port_mapping",
    "deep_recon",
]

BUILTIN_PLAYBOOKS: dict[str, PlaybookConfig] = {
    "wide_recon": PlaybookConfig(
        name="wide_recon",
        description="Full 7-stage recon pipeline with high concurrency. Best for large targets with many subdomains.",
        stages=[StageConfig(name=s) for s in _ALL_RECON_STAGES],
        concurrency=ConcurrencyConfig(heavy=2, light=8),
    ),
    "deep_webapp": PlaybookConfig(
        name="deep_webapp",
        description="Focused on web application testing. Skips active discovery, emphasizes deep recon and fingerprinting.",
        stages=[
            StageConfig(name="passive_discovery"),
            StageConfig(name="active_discovery", enabled=False),
            StageConfig(name="liveness_dns"),
            StageConfig(name="subdomain_takeover", enabled=False),
            StageConfig(name="fingerprinting"),
            StageConfig(name="port_mapping"),
            StageConfig(name="deep_recon"),
        ],
        concurrency=ConcurrencyConfig(heavy=3, light=6),
    ),
    "api_focused": PlaybookConfig(
        name="api_focused",
        description="Minimal recon, maximum parameter discovery. For targets with known API surface.",
        stages=[
            StageConfig(name="passive_discovery"),
            StageConfig(name="active_discovery", enabled=False),
            StageConfig(name="liveness_dns"),
            StageConfig(name="subdomain_takeover", enabled=False),
            StageConfig(name="fingerprinting", enabled=False),
            StageConfig(name="port_mapping"),
            StageConfig(name="deep_recon"),
        ],
        concurrency=ConcurrencyConfig(heavy=1, light=4),
    ),
    "cloud_first": PlaybookConfig(
        name="cloud_first",
        description="Full recon plus aggressive cloud enumeration. For targets with significant cloud footprint.",
        stages=[StageConfig(name=s) for s in _ALL_RECON_STAGES],
        concurrency=ConcurrencyConfig(heavy=2, light=6),
    ),
}

DEFAULT_PLAYBOOK = "wide_recon"


def get_playbook(name: str) -> PlaybookConfig:
    """Return a playbook config by name, falling back to the default."""
    return BUILTIN_PLAYBOOKS.get(name, BUILTIN_PLAYBOOKS[DEFAULT_PLAYBOOK])
