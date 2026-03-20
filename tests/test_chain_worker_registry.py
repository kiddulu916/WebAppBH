# tests/test_chain_worker_registry.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.models import (
    ChainViability, EvaluationResult, ChainResult, TargetFindings,
)


def test_base_chain_template_attributes():
    from workers.chain_worker.registry import BaseChainTemplate
    assert hasattr(BaseChainTemplate, "name")
    assert hasattr(BaseChainTemplate, "category")
    assert hasattr(BaseChainTemplate, "severity_on_success")
    assert hasattr(BaseChainTemplate, "requires_accounts")


def test_register_chain_decorator():
    from workers.chain_worker.registry import (
        BaseChainTemplate, register_chain, get_registry, clear_registry,
    )
    clear_registry()

    @register_chain
    class FakeChain(BaseChainTemplate):
        name = "fake_chain"
        category = "test"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    registry = get_registry()
    assert "fake_chain" in registry
    assert isinstance(registry["fake_chain"], FakeChain)
    clear_registry()


def test_register_multiple_chains():
    from workers.chain_worker.registry import (
        BaseChainTemplate, register_chain, get_registry, clear_registry,
    )
    clear_registry()

    @register_chain
    class Chain1(BaseChainTemplate):
        name = "chain_1"
        category = "cat_a"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    @register_chain
    class Chain2(BaseChainTemplate):
        name = "chain_2"
        category = "cat_b"
        severity_on_success = "high"
        requires_accounts = True
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    registry = get_registry()
    assert len(registry) == 2
    assert registry["chain_2"].requires_accounts is True
    clear_registry()


def test_get_chains_by_category():
    from workers.chain_worker.registry import (
        BaseChainTemplate, register_chain, get_chains_by_category, clear_registry,
    )
    clear_registry()

    @register_chain
    class ChainA(BaseChainTemplate):
        name = "chain_a"
        category = "ssrf"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    @register_chain
    class ChainB(BaseChainTemplate):
        name = "chain_b"
        category = "xss"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    @register_chain
    class ChainC(BaseChainTemplate):
        name = "chain_c"
        category = "ssrf"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    ssrf_chains = get_chains_by_category("ssrf")
    assert len(ssrf_chains) == 2
    xss_chains = get_chains_by_category("xss")
    assert len(xss_chains) == 1
    clear_registry()


def test_duplicate_name_raises():
    from workers.chain_worker.registry import (
        BaseChainTemplate, register_chain, clear_registry,
    )
    clear_registry()

    @register_chain
    class ChainOrig(BaseChainTemplate):
        name = "duplicate"
        category = "test"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    with pytest.raises(ValueError, match="already registered"):
        @register_chain
        class ChainDup(BaseChainTemplate):
            name = "duplicate"
            category = "test"
            severity_on_success = "critical"
            requires_accounts = False
            async def evaluate(self, findings):
                return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
            async def execute(self, context):
                return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    clear_registry()
