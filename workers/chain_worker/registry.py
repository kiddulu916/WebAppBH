# workers/chain_worker/registry.py
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from workers.chain_worker.models import ChainResult, EvaluationResult, TargetFindings

_REGISTRY: dict[str, BaseChainTemplate] = {}

class ChainContext:
    def __init__(self, *, target_id: int, findings: TargetFindings, matched_findings: dict[str, Any],
                 http_session: Any = None, zap_client: Any = None, msf_client: Any = None,
                 scope_manager: Any = None, browser: Any = None, evidence_dir: str = "",
                 step_delay_ms: int = 500, log: Any = None):
        self.target_id = target_id
        self.findings = findings
        self.matched_findings = matched_findings
        self.http_session = http_session
        self.zap_client = zap_client
        self.msf_client = msf_client
        self.scope_manager = scope_manager
        self.browser = browser
        self.evidence_dir = evidence_dir
        self.step_delay_ms = step_delay_ms
        self.log = log

class BaseChainTemplate(ABC):
    name: str = ""
    category: str = ""
    severity_on_success: str = "critical"
    requires_accounts: bool = False
    @abstractmethod
    async def evaluate(self, findings: TargetFindings) -> EvaluationResult: pass
    @abstractmethod
    async def execute(self, context: ChainContext) -> ChainResult: pass

def register_chain(cls: type[BaseChainTemplate]) -> type[BaseChainTemplate]:
    if cls.name in _REGISTRY:
        raise ValueError(f"Chain '{cls.name}' already registered")
    _REGISTRY[cls.name] = cls()
    return cls

def get_registry() -> dict[str, BaseChainTemplate]: return _REGISTRY
def get_chains_by_category(category: str) -> list[BaseChainTemplate]:
    return [c for c in _REGISTRY.values() if c.category == category]
def clear_registry() -> None: _REGISTRY.clear()
def save_registry() -> dict[str, BaseChainTemplate]: return dict(_REGISTRY)
def restore_registry(saved: dict[str, BaseChainTemplate]) -> None:
    _REGISTRY.clear()
    _REGISTRY.update(saved)
