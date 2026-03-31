# M9: Chain Worker & Reporting Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the chain_worker (vulnerability chaining via 180 exploit chain templates) and reporting worker (bug submission report generation).

**Architecture:** Chain worker uses aiohttp + ZAP + MSF + Playwright for multi-step exploit chain verification. Reporting worker generates formatted Markdown reports for bug bounty submission. Both follow the worker template pattern.

**Tech Stack:** Python 3.10, asyncio, aiohttp, pymetasploit3, playwright, python-owasp-zap-v2.4, lib_webbh

**Design docs:**
- `docs/plans/design/2026-03-20-phase12-exploit-chainer-design.md`
- `docs/plans/design/2026-03-29-restructure-11-dashboard-reporting.md` (Part B)
- `docs/plans/design/2026-03-29-restructure-10-database-messaging.md` (ChainFinding, EscalationContext models)

---

# Part A: Chain Worker

## Template Variables

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `chain_worker` |
| `{WORKER_DIR}` | `workers/chain_worker` |
| `{QUEUE_NAME}` | `chain_worker_queue` |
| `{BASE_TOOL_CLASS}` | `ChainTool` |
| `{EXPECTED_STAGE_COUNT}` | `4` |

## Stages

| # | Stage Name | Section ID | Tools | Weight |
|---|-----------|-----------|-------|--------|
| 1 | data_collection | chain.1 | FindingsCollector | LIGHT |
| 2 | chain_evaluation | chain.2 | ChainEvaluator | LIGHT |
| 3 | chain_execution | chain.3 | ChainExecutor | HEAVY |
| 4 | chain_reporting | chain.4 | ChainReporter | LIGHT |

## Tool Weights

```python
TOOL_WEIGHTS = {
    "FindingsCollector": "LIGHT",
    "ChainEvaluator": "LIGHT",
    "ChainExecutor": "HEAVY",
    "ChainReporter": "LIGHT",
}
```

---

## Task 1: Scaffold Chain Worker Directory

**Files:**
- Create: `workers/chain_worker/__init__.py`
- Create: `workers/chain_worker/tools/__init__.py`
- Create: `workers/chain_worker/chains/__init__.py`
- Create: `workers/chain_worker/requirements.txt`
- Create: `tests/test_chain_worker/__init__.py`

**Step 1: Create directory structure**

```bash
mkdir -p workers/chain_worker/tools workers/chain_worker/chains tests/test_chain_worker
touch workers/chain_worker/__init__.py workers/chain_worker/tools/__init__.py
touch workers/chain_worker/chains/__init__.py
touch tests/test_chain_worker/__init__.py
```

**Step 2: Create requirements.txt**

```txt
# workers/chain_worker/requirements.txt
# lib_webbh installed from shared/ in Dockerfile
aiohttp>=3.9
python-owasp-zap-v2.4>=0.0.21
pymetasploit3>=1.0.3
playwright>=1.40
```

**Step 3: Commit**

```bash
git add workers/chain_worker/ tests/test_chain_worker/
git commit -m "chore(chain_worker): scaffold worker directory structure"
```

---

## Task 2: Concurrency Module

**Files:**
- Create: `workers/chain_worker/concurrency.py`
- Test: `tests/test_chain_worker/test_concurrency.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_concurrency.py
import asyncio


def test_get_semaphores_returns_bounded_semaphores():
    from workers.chain_worker.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.Semaphore)
    assert isinstance(light, asyncio.Semaphore)


def test_tool_weights_contains_all_tools():
    from workers.chain_worker.concurrency import TOOL_WEIGHTS

    expected_tools = {
        "FindingsCollector", "ChainEvaluator",
        "ChainExecutor", "ChainReporter",
    }
    assert set(TOOL_WEIGHTS.keys()) == expected_tools


def test_tool_weights_valid_values():
    from workers.chain_worker.concurrency import TOOL_WEIGHTS

    for tool, weight in TOOL_WEIGHTS.items():
        assert weight in ("HEAVY", "LIGHT"), f"{tool} has invalid weight: {weight}"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker/test_concurrency.py -v`

**Step 3: Write concurrency.py**

```python
# workers/chain_worker/concurrency.py
import asyncio
import os

HEAVY_LIMIT = 1  # Only one chain executing at a time (chains may interact with same target)
LIGHT_LIMIT = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))

TOOL_WEIGHTS = {
    "FindingsCollector": "LIGHT",
    "ChainEvaluator": "LIGHT",
    "ChainExecutor": "HEAVY",
    "ChainReporter": "LIGHT",
}


def get_semaphores() -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
    return asyncio.Semaphore(HEAVY_LIMIT), asyncio.Semaphore(LIGHT_LIMIT)
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/concurrency.py tests/test_chain_worker/test_concurrency.py
git commit -m "feat(chain_worker): add concurrency module with tool weights"
```

---

## Task 3: Base Tool Class

**Files:**
- Create: `workers/chain_worker/base_tool.py`
- Test: `tests/test_chain_worker/test_base_tool.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_base_tool.py
import pytest
from abc import ABC

pytestmark = pytest.mark.anyio


def test_base_tool_is_abstract():
    from workers.chain_worker.base_tool import ChainTool

    assert issubclass(ChainTool, ABC)

    with pytest.raises(TypeError):
        ChainTool()


def test_base_tool_has_worker_type():
    from workers.chain_worker.base_tool import ChainTool

    assert ChainTool.worker_type == "chain_worker"
```

**Step 2: Run test, verify fail.**

**Step 3: Write base_tool.py**

```python
# workers/chain_worker/base_tool.py
from abc import ABC, abstractmethod
from lib_webbh import get_session, Vulnerability


class ChainTool(ABC):
    """Abstract base for all chain_worker tools."""

    worker_type = "chain_worker"

    @abstractmethod
    async def execute(self, target_id: int, **kwargs):
        """Run this tool against the target. Must be implemented by subclasses."""
        ...

    async def save_vulnerability(self, target_id, **kwargs):
        """Helper: insert a Vulnerability record."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                worker_type=self.worker_type,
                **kwargs,
            )
            session.add(vuln)
            await session.commit()
            return vuln.id

    async def scope_check(self, target_id: int, value: str) -> bool:
        """Check if a value is in scope before processing."""
        from lib_webbh.scope import ScopeManager
        async with get_session() as session:
            from lib_webbh.database import Target
            target = await session.get(Target, target_id)
            if not target or not target.scope_config:
                return False
            manager = ScopeManager(target.scope_config)
            return manager.check(value).in_scope
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/base_tool.py tests/test_chain_worker/test_base_tool.py
git commit -m "feat(chain_worker): add abstract base tool class"
```

---

## Task 4: Chain Template Registry & Base Template

**Files:**
- Create: `workers/chain_worker/chains/registry.py`
- Create: `workers/chain_worker/chains/base_template.py`
- Test: `tests/test_chain_worker/test_chain_registry.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_chain_registry.py
import pytest
from dataclasses import dataclass

pytestmark = pytest.mark.anyio


def test_registry_decorator_registers_chain():
    from workers.chain_worker.chains.registry import register_chain, get_all_chains, _CHAIN_REGISTRY

    _CHAIN_REGISTRY.clear()  # Reset for test isolation

    @register_chain
    class FakeChain:
        name = "fake_chain"
        category = "test"

    chains = get_all_chains()
    assert len(chains) == 1
    assert chains[0].name == "fake_chain"


def test_base_template_is_abstract():
    from workers.chain_worker.chains.base_template import BaseChainTemplate
    from abc import ABC

    assert issubclass(BaseChainTemplate, ABC)

    with pytest.raises(TypeError):
        BaseChainTemplate()


def test_chain_viability_enum():
    from workers.chain_worker.chains.base_template import ChainViability

    assert hasattr(ChainViability, "VIABLE")
    assert hasattr(ChainViability, "PARTIAL")
    assert hasattr(ChainViability, "NOT_VIABLE")
    assert hasattr(ChainViability, "AWAITING_ACCOUNTS")
```

**Step 2: Run test, verify fail.**

**Step 3: Write registry.py**

```python
# workers/chain_worker/chains/registry.py

_CHAIN_REGISTRY: list = []


def register_chain(cls):
    """Decorator to register a chain template class."""
    _CHAIN_REGISTRY.append(cls)
    return cls


def get_all_chains():
    """Return all registered chain template classes."""
    return list(_CHAIN_REGISTRY)
```

**Step 4: Write base_template.py**

```python
# workers/chain_worker/chains/base_template.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class ChainViability(Enum):
    VIABLE = "viable"
    PARTIAL = "partial"
    NOT_VIABLE = "not_viable"
    AWAITING_ACCOUNTS = "awaiting_accounts"


@dataclass
class ChainStep:
    action: str
    target: str
    result: str
    timestamp: str
    request: dict | None = None
    response: dict | None = None
    screenshot_path: str | None = None


@dataclass
class ChainResult:
    success: bool
    steps: list[ChainStep] = field(default_factory=list)
    proof_of_concept: str = ""
    error: str | None = None


@dataclass
class TargetFindings:
    target_id: int
    vulnerabilities: list = field(default_factory=list)
    assets: list = field(default_factory=list)
    parameters: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    test_accounts: dict = field(default_factory=dict)


@dataclass
class ChainContext:
    target_id: int
    findings: TargetFindings
    matched_findings: list = field(default_factory=list)
    scope_config: dict = field(default_factory=dict)


class BaseChainTemplate(ABC):
    """Abstract base for all exploit chain templates."""

    name: str = ""
    category: str = ""
    severity_on_success: str = "critical"
    requires_accounts: bool = False

    @abstractmethod
    async def evaluate(self, findings: TargetFindings) -> ChainViability:
        """Evaluate whether this chain is viable given current findings."""
        ...

    @abstractmethod
    async def execute(self, context: ChainContext) -> ChainResult:
        """Execute the chain steps. Returns ChainResult with evidence."""
        ...
```

**Step 5: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/chains/ tests/test_chain_worker/test_chain_registry.py
git commit -m "feat(chain_worker): add chain template registry and base template"
```

---

## Task 5: FindingsCollector Tool

**Files:**
- Create: `workers/chain_worker/tools/findings_collector.py`
- Test: `tests/test_chain_worker/test_findings_collector.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_findings_collector.py
import pytest

pytestmark = pytest.mark.anyio


def test_findings_collector_subclasses_base():
    from workers.chain_worker.tools.findings_collector import FindingsCollector
    from workers.chain_worker.base_tool import ChainTool

    assert issubclass(FindingsCollector, ChainTool)


def test_findings_collector_has_execute():
    from workers.chain_worker.tools.findings_collector import FindingsCollector

    tool = FindingsCollector()
    assert hasattr(tool, "execute")
    assert callable(tool.execute)
```

**Step 2: Run test, verify fail.**

**Step 3: Implement FindingsCollector**

```python
# workers/chain_worker/tools/findings_collector.py
import json
from pathlib import Path

from workers.chain_worker.base_tool import ChainTool
from workers.chain_worker.chains.base_template import TargetFindings
from lib_webbh import get_session
from lib_webbh.database import Vulnerability, Asset, Parameter, Observation


class FindingsCollector(ChainTool):
    """Collects all findings for a target into a TargetFindings dataclass."""

    async def execute(self, target_id: int, **kwargs) -> TargetFindings:
        async with get_session() as session:
            from sqlalchemy import select

            vulns = await session.execute(
                select(Vulnerability).where(Vulnerability.target_id == target_id)
            )
            assets = await session.execute(
                select(Asset).where(Asset.target_id == target_id)
            )
            params = await session.execute(
                select(Parameter).where(Parameter.target_id == target_id)
            )
            obs = await session.execute(
                select(Observation).where(Observation.target_id == target_id)
            )

            # Load test account credentials
            test_accounts = {}
            creds_path = Path(f"shared/config/{target_id}/credentials.json")
            if creds_path.exists():
                test_accounts = json.loads(creds_path.read_text())

            return TargetFindings(
                target_id=target_id,
                vulnerabilities=list(vulns.scalars().all()),
                assets=list(assets.scalars().all()),
                parameters=list(params.scalars().all()),
                observations=list(obs.scalars().all()),
                test_accounts=test_accounts,
            )
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/tools/findings_collector.py tests/test_chain_worker/test_findings_collector.py
git commit -m "feat(chain_worker): add FindingsCollector tool"
```

---

## Task 6: ChainEvaluator Tool

**Files:**
- Create: `workers/chain_worker/tools/chain_evaluator.py`
- Test: `tests/test_chain_worker/test_chain_evaluator.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_chain_evaluator.py
import pytest

pytestmark = pytest.mark.anyio


def test_chain_evaluator_subclasses_base():
    from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
    from workers.chain_worker.base_tool import ChainTool

    assert issubclass(ChainEvaluator, ChainTool)


def test_chain_evaluator_has_execute():
    from workers.chain_worker.tools.chain_evaluator import ChainEvaluator

    tool = ChainEvaluator()
    assert hasattr(tool, "execute")
    assert callable(tool.execute)
```

**Step 2: Run test, verify fail.**

**Step 3: Implement ChainEvaluator**

```python
# workers/chain_worker/tools/chain_evaluator.py
from workers.chain_worker.base_tool import ChainTool
from workers.chain_worker.chains.registry import get_all_chains
from workers.chain_worker.chains.base_template import (
    ChainViability,
    TargetFindings,
)
from lib_webbh import setup_logger

logger = setup_logger("chain_evaluator")


class ChainEvaluator(ChainTool):
    """Evaluates all registered chain templates against current findings."""

    async def execute(self, target_id: int, **kwargs):
        findings: TargetFindings = kwargs.get("findings")
        if not findings:
            logger.warning("No findings provided to evaluator", target_id=target_id)
            return {"viable": [], "partial": [], "awaiting_accounts": []}

        viable = []
        partial = []
        awaiting = []

        for chain_cls in get_all_chains():
            chain = chain_cls()
            try:
                result = await chain.evaluate(findings)
                if result == ChainViability.VIABLE:
                    viable.append(chain)
                elif result == ChainViability.PARTIAL:
                    partial.append(chain)
                elif result == ChainViability.AWAITING_ACCOUNTS:
                    awaiting.append(chain)
            except Exception as e:
                logger.error(
                    "Chain evaluation failed",
                    chain=chain.name,
                    error=str(e),
                )

        logger.info(
            "Chain evaluation complete",
            target_id=target_id,
            viable=len(viable),
            partial=len(partial),
            awaiting_accounts=len(awaiting),
        )

        return {
            "viable": viable,
            "partial": partial,
            "awaiting_accounts": awaiting,
        }
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/tools/chain_evaluator.py tests/test_chain_worker/test_chain_evaluator.py
git commit -m "feat(chain_worker): add ChainEvaluator tool"
```

---

## Task 7: ChainExecutor Tool

**Files:**
- Create: `workers/chain_worker/tools/chain_executor.py`
- Test: `tests/test_chain_worker/test_chain_executor.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_chain_executor.py
import pytest

pytestmark = pytest.mark.anyio


def test_chain_executor_subclasses_base():
    from workers.chain_worker.tools.chain_executor import ChainExecutor
    from workers.chain_worker.base_tool import ChainTool

    assert issubclass(ChainExecutor, ChainTool)


def test_chain_executor_has_execute():
    from workers.chain_worker.tools.chain_executor import ChainExecutor

    tool = ChainExecutor()
    assert hasattr(tool, "execute")
    assert callable(tool.execute)
```

**Step 2: Run test, verify fail.**

**Step 3: Implement ChainExecutor**

```python
# workers/chain_worker/tools/chain_executor.py
import asyncio
import os

from workers.chain_worker.base_tool import ChainTool
from workers.chain_worker.chains.base_template import (
    ChainContext,
    ChainResult,
    TargetFindings,
)
from lib_webbh import setup_logger, get_session
from lib_webbh.database import Target

logger = setup_logger("chain_executor")

CHAIN_STEP_DELAY_MS = int(os.environ.get("CHAIN_STEP_DELAY_MS", "500"))


class ChainExecutor(ChainTool):
    """Executes viable chain templates sequentially against the target."""

    async def execute(self, target_id: int, **kwargs):
        viable_chains = kwargs.get("viable", [])
        findings: TargetFindings = kwargs.get("findings")

        if not viable_chains:
            logger.info("No viable chains to execute", target_id=target_id)
            return []

        # Build context
        async with get_session() as session:
            target = await session.get(Target, target_id)
            scope_config = target.scope_config or {} if target else {}

        context = ChainContext(
            target_id=target_id,
            findings=findings,
            scope_config=scope_config,
        )

        results = []
        for chain in viable_chains:
            # Scope check before execution
            logger.info(
                "Executing chain",
                chain=chain.name,
                category=chain.category,
                target_id=target_id,
            )

            try:
                result: ChainResult = await chain.execute(context)
                results.append((chain, result))

                if result.success:
                    logger.info(
                        "Chain succeeded",
                        chain=chain.name,
                        steps=len(result.steps),
                        target_id=target_id,
                    )
                else:
                    logger.info(
                        "Chain failed",
                        chain=chain.name,
                        error=result.error,
                        target_id=target_id,
                    )

            except Exception as e:
                logger.error(
                    "Chain execution error",
                    chain=chain.name,
                    error=str(e),
                    target_id=target_id,
                )
                results.append((chain, ChainResult(success=False, error=str(e))))

            # Rate limiting between chains
            await asyncio.sleep(CHAIN_STEP_DELAY_MS / 1000)

        return results
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/tools/chain_executor.py tests/test_chain_worker/test_chain_executor.py
git commit -m "feat(chain_worker): add ChainExecutor tool"
```

---

## Task 8: ChainReporter Tool

**Files:**
- Create: `workers/chain_worker/tools/chain_reporter.py`
- Test: `tests/test_chain_worker/test_chain_reporter.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_chain_reporter.py
import pytest

pytestmark = pytest.mark.anyio


def test_chain_reporter_subclasses_base():
    from workers.chain_worker.tools.chain_reporter import ChainReporter
    from workers.chain_worker.base_tool import ChainTool

    assert issubclass(ChainReporter, ChainTool)


def test_chain_reporter_has_execute():
    from workers.chain_worker.tools.chain_reporter import ChainReporter

    tool = ChainReporter()
    assert hasattr(tool, "execute")
    assert callable(tool.execute)
```

**Step 2: Run test, verify fail.**

**Step 3: Implement ChainReporter**

```python
# workers/chain_worker/tools/chain_reporter.py
from workers.chain_worker.base_tool import ChainTool
from workers.chain_worker.chains.base_template import ChainResult
from lib_webbh import get_session, setup_logger
from lib_webbh.database import Vulnerability, Observation, ChainFinding
from lib_webbh.messaging import push_task

logger = setup_logger("chain_reporter")


class ChainReporter(ChainTool):
    """Reports successful chain results as Vulnerability + ChainFinding records."""

    async def execute(self, target_id: int, **kwargs):
        chain_results = kwargs.get("results", [])

        for chain, result in chain_results:
            if not result.success:
                continue

            # Save vulnerability
            vuln_id = await self.save_vulnerability(
                target_id=target_id,
                severity=chain.severity_on_success,
                title=f"CHAINED: {chain.name}",
                vuln_type="chain",
                source_tool=f"chain:{chain.name}",
                confirmed=True,
                description=result.proof_of_concept,
                evidence={
                    "steps": [
                        {
                            "action": step.action,
                            "target": step.target,
                            "result": step.result,
                            "timestamp": step.timestamp,
                            "screenshot": step.screenshot_path,
                        }
                        for step in result.steps
                    ]
                },
            )

            # Save observation with attack path
            async with get_session() as session:
                obs = Observation(
                    target_id=target_id,
                    observation_type="chain_result",
                    data={
                        "chain_type": chain.name,
                        "chain_category": chain.category,
                        "steps": [
                            {
                                "action": s.action,
                                "target": s.target,
                                "result": s.result,
                                "screenshot": s.screenshot_path,
                            }
                            for s in result.steps
                        ],
                        "total_steps": len(result.steps),
                    },
                )
                session.add(obs)
                await session.commit()

            # Push SSE event
            await push_task(
                f"events:{target_id}",
                {
                    "event": "chain_success",
                    "chain": chain.name,
                    "severity": chain.severity_on_success,
                    "steps": len(result.steps),
                    "target_id": target_id,
                },
            )

            logger.info(
                "Chain reported",
                chain=chain.name,
                vuln_id=vuln_id,
                target_id=target_id,
            )
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/tools/chain_reporter.py tests/test_chain_worker/test_chain_reporter.py
git commit -m "feat(chain_worker): add ChainReporter tool"
```

---

## Task 9: Chain Template Stubs (Auth/Session Category — 22 chains)

**Files:**
- Create: `workers/chain_worker/chains/auth_session.py`
- Test: `tests/test_chain_worker/test_chain_templates.py`

Each chain category gets its own file. Chain templates follow the `@register_chain` decorator pattern. Initially implement as stubs with `evaluate()` checking for required preconditions and `execute()` raising `NotImplementedError` — full implementations are filled in during integration testing against real targets.

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_chain_templates.py
import pytest

pytestmark = pytest.mark.anyio


def test_auth_session_chains_registered():
    # Force import to trigger registration
    import workers.chain_worker.chains.auth_session  # noqa: F401
    from workers.chain_worker.chains.registry import get_all_chains, _CHAIN_REGISTRY

    auth_chains = [c for c in get_all_chains() if c.category == "auth_session"]
    assert len(auth_chains) == 22


def test_all_chain_templates_have_required_attrs():
    # Import all chain modules
    import workers.chain_worker.chains.auth_session  # noqa: F401
    from workers.chain_worker.chains.registry import get_all_chains

    for chain_cls in get_all_chains():
        chain = chain_cls()
        assert hasattr(chain, "name"), f"{chain_cls.__name__} missing name"
        assert hasattr(chain, "category"), f"{chain_cls.__name__} missing category"
        assert hasattr(chain, "severity_on_success"), f"{chain_cls.__name__} missing severity_on_success"
        assert hasattr(chain, "evaluate"), f"{chain_cls.__name__} missing evaluate"
        assert hasattr(chain, "execute"), f"{chain_cls.__name__} missing execute"
```

**Step 2: Run test, verify fail.**

**Step 3: Implement auth_session.py with 22 chain template stubs**

Each chain template subclasses `BaseChainTemplate`, implements `evaluate()` to check for required vulnerability types in `TargetFindings`, and implements `execute()` with the chain step logic. Initially, `execute()` returns `ChainResult(success=False, error="not yet implemented")` — stubs are populated during integration testing.

```python
# workers/chain_worker/chains/auth_session.py
from workers.chain_worker.chains.base_template import (
    BaseChainTemplate, ChainViability, ChainResult, TargetFindings, ChainContext,
)
from workers.chain_worker.chains.registry import register_chain


@register_chain
class InfoToAccess(BaseChainTemplate):
    name = "info_to_access"
    category = "auth_session"

    async def evaluate(self, findings: TargetFindings) -> ChainViability:
        has_info_leak = any(
            v.vuln_type in ("info_leak", "config_leak", "credential_exposure")
            for v in findings.vulnerabilities
        )
        return ChainViability.VIABLE if has_info_leak else ChainViability.NOT_VIABLE

    async def execute(self, context: ChainContext) -> ChainResult:
        return ChainResult(success=False, error="not yet implemented")


# ... repeat for all 22 auth/session chains (templates 1-22 from design doc)
# Each chain class follows the same pattern:
# - @register_chain decorator
# - name and category attributes
# - evaluate() checks TargetFindings for required preconditions
# - execute() stub returning not-yet-implemented
```

The full list of 22 chains in this file:
1. InfoToAccess
2. IdorAccountTakeover
3. OAuthDirtyDancing
4. TwoFaBypass
5. MassAssignmentPrivesc
6. SamlMisconfigImpersonation
7. SessionTokenRefererLeak
8. TimingAttackBruteForce
9. JwtWeaknessAuthBypass
10. PasswordResetTokenPrediction
11. SamlAssertionReplay
12. MagicLinkTokenReuse
13. OAuthPkceDowngrade
14. RememberMeTokenWeakness
15. ConcurrentSessionConfusion
16. AccountRecoveryBruteForce
17. DeviceBindingBypass
18. RegistrationToctou
19. AuthTokenWebsocketTheft
20. OpenRedirectTokenTheft
21. CsrfEmailChangeAto
22. SubdomainTakeoverCookieSteal

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/chains/auth_session.py tests/test_chain_worker/test_chain_templates.py
git commit -m "feat(chain_worker): add 22 auth/session chain template stubs"
```

---

## Task 10: Remaining Chain Template Categories

**Files:**
- Create: `workers/chain_worker/chains/injection_execution.py` (22 chains, templates 23-44)
- Create: `workers/chain_worker/chains/ssrf_infrastructure.py` (20 chains, templates 45-64)
- Create: `workers/chain_worker/chains/xss_client_side.py` (19 chains, templates 65-83)
- Create: `workers/chain_worker/chains/file_processing.py` (19 chains, templates 84-102)
- Create: `workers/chain_worker/chains/header_protocol.py` (20 chains, templates 103-122)
- Create: `workers/chain_worker/chains/access_control_logic.py` (21 chains, templates 123-143)
- Create: `workers/chain_worker/chains/bypass.py` (19 chains, templates 144-162)
- Create: `workers/chain_worker/chains/platform_protocol.py` (18 chains, templates 163-180)

Each file follows the same pattern as `auth_session.py` — `@register_chain` decorated classes with `evaluate()` checking preconditions and `execute()` stubs.

**Step 1: Update test**

```python
# Add to tests/test_chain_worker/test_chain_templates.py

def test_all_180_chains_registered():
    # Import all chain modules
    import workers.chain_worker.chains.auth_session  # noqa: F401
    import workers.chain_worker.chains.injection_execution  # noqa: F401
    import workers.chain_worker.chains.ssrf_infrastructure  # noqa: F401
    import workers.chain_worker.chains.xss_client_side  # noqa: F401
    import workers.chain_worker.chains.file_processing  # noqa: F401
    import workers.chain_worker.chains.header_protocol  # noqa: F401
    import workers.chain_worker.chains.access_control_logic  # noqa: F401
    import workers.chain_worker.chains.bypass  # noqa: F401
    import workers.chain_worker.chains.platform_protocol  # noqa: F401
    from workers.chain_worker.chains.registry import get_all_chains

    assert len(get_all_chains()) == 180


def test_chain_categories():
    import workers.chain_worker.chains.auth_session  # noqa: F401
    import workers.chain_worker.chains.injection_execution  # noqa: F401
    import workers.chain_worker.chains.ssrf_infrastructure  # noqa: F401
    import workers.chain_worker.chains.xss_client_side  # noqa: F401
    import workers.chain_worker.chains.file_processing  # noqa: F401
    import workers.chain_worker.chains.header_protocol  # noqa: F401
    import workers.chain_worker.chains.access_control_logic  # noqa: F401
    import workers.chain_worker.chains.bypass  # noqa: F401
    import workers.chain_worker.chains.platform_protocol  # noqa: F401
    from workers.chain_worker.chains.registry import get_all_chains

    categories = {}
    for chain_cls in get_all_chains():
        chain = chain_cls()
        categories.setdefault(chain.category, 0)
        categories[chain.category] += 1

    assert categories == {
        "auth_session": 22,
        "injection_execution": 22,
        "ssrf_infrastructure": 20,
        "xss_client_side": 19,
        "file_processing": 19,
        "header_protocol": 20,
        "access_control_logic": 21,
        "bypass": 19,
        "platform_protocol": 18,
    }
```

**Step 2: Run test, verify fail.**

**Step 3: Implement all 8 remaining chain category files following the same pattern as auth_session.py. Each chain template gets a unique name from the design doc (templates 23-180).**

Reference: `docs/plans/design/2026-03-20-phase12-exploit-chainer-design.md` sections 2.2–2.9 for exact chain names and categories.

**Step 4: Run test, verify all 180 chains registered. Commit.**

```bash
git add workers/chain_worker/chains/
git commit -m "feat(chain_worker): add remaining 158 chain template stubs (180 total)"
```

---

## Task 11: Pipeline Module

**Files:**
- Create: `workers/chain_worker/pipeline.py`
- Test: `tests/test_chain_worker/test_pipeline.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker/test_pipeline.py
import pytest

pytestmark = pytest.mark.anyio


def test_pipeline_stages_defined():
    from workers.chain_worker.pipeline import STAGES

    assert len(STAGES) == 4
    assert all(hasattr(s, "name") for s in STAGES)
    assert all(hasattr(s, "section_id") for s in STAGES)
    assert all(hasattr(s, "tools") for s in STAGES)


def test_pipeline_stages_ordered():
    from workers.chain_worker.pipeline import STAGES

    names = [s.name for s in STAGES]
    assert names == [
        "data_collection",
        "chain_evaluation",
        "chain_execution",
        "chain_reporting",
    ]


def test_pipeline_all_tools_have_weights():
    from workers.chain_worker.pipeline import STAGES
    from workers.chain_worker.concurrency import TOOL_WEIGHTS

    all_tools = set()
    for stage in STAGES:
        for tool_cls in stage.tools:
            all_tools.add(tool_cls.__name__)

    assert all_tools == set(TOOL_WEIGHTS.keys())
```

**Step 2: Run test, verify fail.**

**Step 3: Write pipeline.py**

```python
# workers/chain_worker/pipeline.py
from dataclasses import dataclass, field

from .tools.findings_collector import FindingsCollector
from .tools.chain_evaluator import ChainEvaluator
from .tools.chain_executor import ChainExecutor
from .tools.chain_reporter import ChainReporter


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


STAGES = [
    Stage(name="data_collection", section_id="chain.1", tools=[FindingsCollector]),
    Stage(name="chain_evaluation", section_id="chain.2", tools=[ChainEvaluator]),
    Stage(name="chain_execution", section_id="chain.3", tools=[ChainExecutor]),
    Stage(name="chain_reporting", section_id="chain.4", tools=[ChainReporter]),
]
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/chain_worker/pipeline.py tests/test_chain_worker/test_pipeline.py
git commit -m "feat(chain_worker): add pipeline with 4 stages"
```

---

## Task 12: Main Entry Point

**Files:**
- Create: `workers/chain_worker/main.py`

**Step 1: Write main.py**

Follow the worker template T6 pattern, using `chain_worker` as the worker type. The chain worker's pipeline is special — stages pass data between each other (findings → evaluator → executor → reporter). The main loop orchestrates this data flow.

```python
# workers/chain_worker/main.py
import asyncio
import os
import socket

from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.database import get_session, JobState
from lib_webbh import setup_logger

from .tools.findings_collector import FindingsCollector
from .tools.chain_evaluator import ChainEvaluator
from .tools.chain_executor import ChainExecutor
from .tools.chain_reporter import ChainReporter

# Import all chain templates to trigger registration
from .chains import auth_session, injection_execution, ssrf_infrastructure  # noqa: F401
from .chains import xss_client_side, file_processing, header_protocol  # noqa: F401
from .chains import access_control_logic, bypass, platform_protocol  # noqa: F401

logger = setup_logger("chain_worker")

WORKER_TYPE = "chain_worker"


async def run_pipeline(target_id: int):
    """Run chain worker pipeline: collect → evaluate → execute → report."""
    from datetime import datetime, timezone
    from sqlalchemy import update

    # Stage 1: Collect findings
    logger.info("Stage started", stage="data_collection", section_id="chain.1")
    collector = FindingsCollector()
    findings = await collector.execute(target_id)
    logger.info("Stage complete", stage="data_collection")

    # Stage 2: Evaluate chains
    logger.info("Stage started", stage="chain_evaluation", section_id="chain.2")
    evaluator = ChainEvaluator()
    evaluation = await evaluator.execute(target_id, findings=findings)
    logger.info("Stage complete", stage="chain_evaluation")

    # Stage 3: Execute viable chains
    logger.info("Stage started", stage="chain_execution", section_id="chain.3")
    executor = ChainExecutor()
    results = await executor.execute(
        target_id, viable=evaluation["viable"], findings=findings
    )
    logger.info("Stage complete", stage="chain_execution")

    # Stage 4: Report results
    logger.info("Stage started", stage="chain_reporting", section_id="chain.4")
    reporter = ChainReporter()
    await reporter.execute(target_id, results=results)
    logger.info("Stage complete", stage="chain_reporting")


async def main():
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"

    async for message in listen_priority_queues(
        f"{WORKER_TYPE}_queue", consumer_group, consumer_name
    ):
        target_id = message["payload"]["target_id"]
        logger.info("Job received", target_id=target_id)

        try:
            from datetime import datetime, timezone

            async with get_session() as session:
                job = JobState(
                    target_id=target_id,
                    worker_type=WORKER_TYPE,
                    status="running",
                    started_at=datetime.now(timezone.utc),
                )
                session.add(job)
                await session.commit()

            await run_pipeline(target_id)

            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.worker_type == WORKER_TYPE)
                    .values(
                        status="complete",
                        completed_at=datetime.now(timezone.utc),
                    )
                )
                await session.commit()

        except Exception as e:
            logger.error("Job failed", target_id=target_id, error=str(e))
            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.worker_type == WORKER_TYPE)
                    .values(status="failed", error=str(e))
                )
                await session.commit()

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 2: Commit**

```bash
git add workers/chain_worker/main.py
git commit -m "feat(chain_worker): add main entry point with priority queue consumer"
```

---

## Task 13: Dockerfile & Docker Compose

**Files:**
- Create: `docker/Dockerfile.chain_worker`
- Modify: `docker-compose.yml`

**Step 1: Write Dockerfile**

```dockerfile
# docker/Dockerfile.chain_worker
FROM webbh-base:latest

# ZAP + MSF + Playwright for chain execution
RUN apt-get update && apt-get install -y \
    zaproxy \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# Playwright for headless screenshots
RUN pip install playwright aiohttp python-owasp-zap-v2.4 pymetasploit3 \
    && playwright install chromium --with-deps

# Copy worker code
COPY workers/chain_worker/ /app/workers/chain_worker/
COPY shared/ /app/shared/

# Install lib_webbh
RUN pip install -e /app/shared/lib_webbh

WORKDIR /app
ENV WORKER_TYPE=chain_worker

CMD ["python", "-m", "workers.chain_worker.main"]
```

**Step 2: Add docker-compose entry**

```yaml
  worker_chain:
    build:
      context: .
      dockerfile: docker/Dockerfile.chain_worker
    depends_on:
      - postgres
      - redis
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=${DB_USER}
      - DB_PASS=${DB_PASS}
      - DB_NAME=${DB_NAME}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - WORKER_TYPE=chain_worker
      - CHAIN_STEP_DELAY_MS=500
    volumes:
      - ./shared/config:/app/shared/config
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 4G
    networks:
      - webbh_net
```

**Step 3: Commit**

```bash
git add docker/Dockerfile.chain_worker docker-compose.yml
git commit -m "feat(chain_worker): add Dockerfile and docker-compose entry"
```

---

## Task 14: Integration Test

**Files:**
- Create: `tests/test_chain_worker/test_integration.py`

**Step 1: Write integration test**

```python
# tests/test_chain_worker/test_integration.py
import pytest

pytestmark = pytest.mark.anyio


async def test_pipeline_all_stages_importable():
    from workers.chain_worker.pipeline import STAGES

    for stage in STAGES:
        for tool_cls in stage.tools:
            tool = tool_cls()
            assert hasattr(tool, "execute")
            assert tool.worker_type == "chain_worker"


def test_all_chains_importable_and_registered():
    from workers.chain_worker.chains.registry import _CHAIN_REGISTRY
    _CHAIN_REGISTRY.clear()

    # Import all chain modules
    import importlib
    import workers.chain_worker.chains.auth_session
    import workers.chain_worker.chains.injection_execution
    import workers.chain_worker.chains.ssrf_infrastructure
    import workers.chain_worker.chains.xss_client_side
    import workers.chain_worker.chains.file_processing
    import workers.chain_worker.chains.header_protocol
    import workers.chain_worker.chains.access_control_logic
    import workers.chain_worker.chains.bypass
    import workers.chain_worker.chains.platform_protocol

    for mod in [
        workers.chain_worker.chains.auth_session,
        workers.chain_worker.chains.injection_execution,
        workers.chain_worker.chains.ssrf_infrastructure,
        workers.chain_worker.chains.xss_client_side,
        workers.chain_worker.chains.file_processing,
        workers.chain_worker.chains.header_protocol,
        workers.chain_worker.chains.access_control_logic,
        workers.chain_worker.chains.bypass,
        workers.chain_worker.chains.platform_protocol,
    ]:
        importlib.reload(mod)

    from workers.chain_worker.chains.registry import get_all_chains
    chains = get_all_chains()
    assert len(chains) == 180

    # Verify unique names
    names = [c().name for c in chains]
    assert len(names) == len(set(names)), "Duplicate chain names found"
```

**Step 2: Run test, verify pass. Commit.**

```bash
git add tests/test_chain_worker/test_integration.py
git commit -m "test(chain_worker): add integration test for pipeline and chain registry"
```

---

# Part B: Reporting Worker

## Template Variables

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `reporting` |
| `{WORKER_DIR}` | `workers/reporting` |
| `{QUEUE_NAME}` | `reporting_queue` |
| `{BASE_TOOL_CLASS}` | `ReportingTool` |
| `{EXPECTED_STAGE_COUNT}` | `1` |

---

## Task 15: Scaffold Reporting Worker

**Files:**
- Create: `workers/reporting/__init__.py`
- Create: `workers/reporting/tools/__init__.py`
- Create: `workers/reporting/requirements.txt`
- Create: `tests/test_reporting/__init__.py`

**Step 1: Create directory structure**

```bash
mkdir -p workers/reporting/tools tests/test_reporting
touch workers/reporting/__init__.py workers/reporting/tools/__init__.py
touch tests/test_reporting/__init__.py
```

**Step 2: Commit**

```bash
git add workers/reporting/ tests/test_reporting/
git commit -m "chore(reporting): scaffold worker directory structure"
```

---

## Task 16: Concurrency, Base Tool, Pipeline (Reporting)

The reporting worker is simple — one stage, one tool. Combine T2/T3/T5 into a single task.

**Files:**
- Create: `workers/reporting/concurrency.py`
- Create: `workers/reporting/base_tool.py`
- Create: `workers/reporting/pipeline.py`
- Test: `tests/test_reporting/test_reporting.py`

**Step 1: Write the failing test**

```python
# tests/test_reporting/test_reporting.py
import asyncio
import pytest
from abc import ABC

pytestmark = pytest.mark.anyio


def test_get_semaphores():
    from workers.reporting.concurrency import get_semaphores

    heavy, light = get_semaphores()
    assert isinstance(heavy, asyncio.Semaphore)
    assert isinstance(light, asyncio.Semaphore)


def test_base_tool_is_abstract():
    from workers.reporting.base_tool import ReportingTool

    assert issubclass(ReportingTool, ABC)
    with pytest.raises(TypeError):
        ReportingTool()


def test_base_tool_has_worker_type():
    from workers.reporting.base_tool import ReportingTool

    assert ReportingTool.worker_type == "reporting"


def test_pipeline_stages():
    from workers.reporting.pipeline import STAGES

    assert len(STAGES) == 1
    assert STAGES[0].name == "generate_reports"
```

**Step 2: Run test, verify fail.**

**Step 3: Write modules**

```python
# workers/reporting/concurrency.py
import asyncio
import os

HEAVY_LIMIT = 1
LIGHT_LIMIT = int(os.environ.get("LIGHT_CONCURRENCY", str(os.cpu_count() or 4)))

TOOL_WEIGHTS = {
    "ReportGenerator": "LIGHT",
}


def get_semaphores() -> tuple[asyncio.Semaphore, asyncio.Semaphore]:
    return asyncio.Semaphore(HEAVY_LIMIT), asyncio.Semaphore(LIGHT_LIMIT)
```

```python
# workers/reporting/base_tool.py
from abc import ABC, abstractmethod


class ReportingTool(ABC):
    """Abstract base for all reporting tools."""

    worker_type = "reporting"

    @abstractmethod
    async def execute(self, target_id: int, **kwargs):
        ...
```

```python
# workers/reporting/pipeline.py
from dataclasses import dataclass, field

from .tools.report_generator import ReportGenerator


@dataclass
class Stage:
    name: str
    section_id: str
    tools: list = field(default_factory=list)


STAGES = [
    Stage(name="generate_reports", section_id="report", tools=[ReportGenerator]),
]
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/reporting/concurrency.py workers/reporting/base_tool.py workers/reporting/pipeline.py tests/test_reporting/test_reporting.py
git commit -m "feat(reporting): add concurrency, base tool, and pipeline modules"
```

---

## Task 17: ReportGenerator Tool

**Files:**
- Create: `workers/reporting/tools/report_generator.py`
- Test: `tests/test_reporting/test_report_generator.py`

**Step 1: Write the failing test**

```python
# tests/test_reporting/test_report_generator.py
import pytest

pytestmark = pytest.mark.anyio


def test_report_generator_subclasses_base():
    from workers.reporting.tools.report_generator import ReportGenerator
    from workers.reporting.base_tool import ReportingTool

    assert issubclass(ReportGenerator, ReportingTool)


def test_report_generator_has_execute():
    from workers.reporting.tools.report_generator import ReportGenerator

    tool = ReportGenerator()
    assert hasattr(tool, "execute")


def test_generate_individual_report_format():
    from workers.reporting.tools.report_generator import ReportGenerator

    tool = ReportGenerator()
    # Mock vulnerability data
    class FakeVuln:
        title = "SQL Injection"
        severity = "critical"
        vuln_type = "sqli"
        section_id = "4.7.5"
        description = "SQL injection in login"
        evidence = {"request": "POST /login", "response": "500"}
        remediation = "Use parameterized queries"
        source_tool = "SqlmapTool"
        worker_type = "input_validation"
        stage_name = "sql_injection"

    class FakeTarget:
        domain = "target.com"

    report = tool._generate_individual_report(FakeVuln(), FakeTarget())
    assert "SQL Injection" in report
    assert "critical" in report.lower() or "Critical" in report
    assert "4.7.5" in report
    assert "parameterized queries" in report
```

**Step 2: Run test, verify fail.**

**Step 3: Implement ReportGenerator**

```python
# workers/reporting/tools/report_generator.py
import json
from pathlib import Path

from workers.reporting.base_tool import ReportingTool
from lib_webbh import get_session, setup_logger
from lib_webbh.database import Vulnerability, ChainFinding, Target, Campaign

logger = setup_logger("report_generator")


class ReportGenerator(ReportingTool):
    """Generates bug submission reports from vulnerability data."""

    async def execute(self, target_id: int, **kwargs):
        async with get_session() as session:
            from sqlalchemy import select

            target = await session.get(Target, target_id)
            if not target:
                logger.error("Target not found", target_id=target_id)
                return

            campaign = None
            if target.campaign_id:
                campaign = await session.get(Campaign, target.campaign_id)

            campaign_id = target.campaign_id or "unknown"
            report_dir = Path(f"shared/reports/{campaign_id}/{target.domain}")
            (report_dir / "individual").mkdir(parents=True, exist_ok=True)
            (report_dir / "chains").mkdir(parents=True, exist_ok=True)

            # Generate individual reports
            vulns = await session.execute(
                select(Vulnerability)
                .where(Vulnerability.target_id == target_id)
                .where(Vulnerability.confirmed == True)
                .where(Vulnerability.false_positive == False)
                .order_by(Vulnerability.severity.desc())
            )

            for vuln in vulns.scalars().all():
                report = self._generate_individual_report(vuln, target)
                slug = f"vuln-{vuln.id:03d}-{vuln.vuln_type}"
                report_path = report_dir / "individual" / f"{slug}.md"
                report_path.write_text(report)
                logger.info("Report generated", vuln_id=vuln.id, path=str(report_path))

            # Generate chain reports
            chains = await session.execute(
                select(ChainFinding)
                .where(ChainFinding.target_id == target_id)
            )

            for chain in chains.scalars().all():
                report = self._generate_chain_report(chain, target)
                slug = f"chain-{chain.id:03d}"
                report_path = report_dir / "chains" / f"{slug}.md"
                report_path.write_text(report)
                logger.info("Chain report generated", chain_id=chain.id, path=str(report_path))

    def _generate_individual_report(self, vuln, target) -> str:
        evidence_section = ""
        if vuln.evidence:
            evidence_section = "\n## Proof of Concept\n"
            if isinstance(vuln.evidence, dict):
                for key, value in vuln.evidence.items():
                    evidence_section += f"\n### {key.title()}\n```\n{value}\n```\n"
            else:
                evidence_section += f"\n```\n{vuln.evidence}\n```\n"

        remediation_section = ""
        if vuln.remediation:
            remediation_section = f"\n## Remediation\n{vuln.remediation}\n"

        return f"""## Title
{vuln.title or vuln.vuln_type} — {target.domain}

## Severity
{(vuln.severity or "unknown").title()}

## Summary
{vuln.description or "No description provided."}

## Affected Endpoint
- Target: {target.domain}
- Worker: {vuln.worker_type or "unknown"}
- Stage: {vuln.stage_name or "unknown"}
- Tool: {vuln.source_tool or "unknown"}
{evidence_section}
{remediation_section}
## References
- OWASP Testing Guide Section {vuln.section_id or "N/A"}
"""

    def _generate_chain_report(self, chain, target) -> str:
        linked = ""
        if chain.linked_vulnerability_ids:
            ids = chain.linked_vulnerability_ids
            linked = "\n".join(f"- Vulnerability #{vid}" for vid in ids)

        return f"""## Title
{chain.chain_description.split('.')[0] if chain.chain_description else "Vulnerability Chain"} — {target.domain}

## Severity
{(chain.severity or "critical").title()}

## Summary
{chain.chain_description or "No description provided."}

## Impact
{chain.total_impact or "See individual findings for impact details."}

## Linked Vulnerabilities
{linked or "No linked vulnerabilities."}
"""
```

**Step 4: Run test, verify pass. Commit.**

```bash
git add workers/reporting/tools/report_generator.py tests/test_reporting/test_report_generator.py
git commit -m "feat(reporting): add ReportGenerator tool with individual and chain reports"
```

---

## Task 18: Reporting Worker Main Entry Point

**Files:**
- Create: `workers/reporting/main.py`

Follow the worker template T6 pattern with `reporting` as worker type.

```python
# workers/reporting/main.py
import asyncio
import socket

from lib_webbh.messaging import listen_priority_queues, get_redis
from lib_webbh.database import get_session, JobState
from lib_webbh import setup_logger

from .pipeline import STAGES
from .concurrency import get_semaphores, TOOL_WEIGHTS

logger = setup_logger("reporting")

WORKER_TYPE = "reporting"


async def run_pipeline(target_id: int):
    """Run all stages sequentially."""
    for stage in STAGES:
        logger.info("Stage started", stage=stage.name)
        for tool_cls in stage.tools:
            tool = tool_cls()
            await tool.execute(target_id)
        logger.info("Stage complete", stage=stage.name)


async def main():
    consumer_group = f"{WORKER_TYPE}_group"
    consumer_name = f"{WORKER_TYPE}_{socket.gethostname()}"

    async for message in listen_priority_queues(
        f"{WORKER_TYPE}_queue", consumer_group, consumer_name
    ):
        target_id = message["payload"]["target_id"]
        logger.info("Job received", target_id=target_id)

        try:
            from datetime import datetime, timezone

            async with get_session() as session:
                job = JobState(
                    target_id=target_id,
                    worker_type=WORKER_TYPE,
                    status="running",
                    started_at=datetime.now(timezone.utc),
                )
                session.add(job)
                await session.commit()

            await run_pipeline(target_id)

            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.worker_type == WORKER_TYPE)
                    .values(
                        status="complete",
                        completed_at=datetime.now(timezone.utc),
                    )
                )
                await session.commit()

        except Exception as e:
            logger.error("Job failed", target_id=target_id, error=str(e))
            async with get_session() as session:
                from sqlalchemy import update
                await session.execute(
                    update(JobState)
                    .where(JobState.target_id == target_id)
                    .where(JobState.worker_type == WORKER_TYPE)
                    .values(status="failed", error=str(e))
                )
                await session.commit()

        r = get_redis()
        await r.xack(message["stream"], consumer_group, message["msg_id"])


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 1: Commit**

```bash
git add workers/reporting/main.py
git commit -m "feat(reporting): add main entry point with priority queue consumer"
```

---

## Task 19: Reporting Dockerfile & Docker Compose

**Files:**
- Create: `docker/Dockerfile.reporting`
- Modify: `docker-compose.yml`

**Step 1: Write Dockerfile**

```dockerfile
# docker/Dockerfile.reporting
FROM webbh-base:latest

# Copy worker code
COPY workers/reporting/ /app/workers/reporting/
COPY shared/ /app/shared/

# Install lib_webbh
RUN pip install -e /app/shared/lib_webbh

WORKDIR /app
ENV WORKER_TYPE=reporting

CMD ["python", "-m", "workers.reporting.main"]
```

**Step 2: Add docker-compose entry**

```yaml
  worker_reporting:
    build:
      context: .
      dockerfile: docker/Dockerfile.reporting
    depends_on:
      - postgres
      - redis
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=${DB_USER}
      - DB_PASS=${DB_PASS}
      - DB_NAME=${DB_NAME}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - WORKER_TYPE=reporting
    volumes:
      - ./shared/reports:/app/shared/reports
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
    networks:
      - webbh_net
```

**Step 3: Commit**

```bash
git add docker/Dockerfile.reporting docker-compose.yml
git commit -m "feat(reporting): add Dockerfile and docker-compose entry"
```

---

## Task 20: Reporting Integration Test

**Files:**
- Create: `tests/test_reporting/test_integration.py`

```python
# tests/test_reporting/test_integration.py
import pytest

pytestmark = pytest.mark.anyio


async def test_reporting_pipeline_importable():
    from workers.reporting.pipeline import STAGES

    for stage in STAGES:
        for tool_cls in stage.tools:
            tool = tool_cls()
            assert hasattr(tool, "execute")
            assert tool.worker_type == "reporting"


def test_report_generator_produces_valid_markdown():
    from workers.reporting.tools.report_generator import ReportGenerator

    tool = ReportGenerator()

    class FakeVuln:
        title = "XSS in Search"
        severity = "high"
        vuln_type = "xss_reflected"
        section_id = "4.7.1"
        description = "Reflected XSS in search parameter"
        evidence = {"request": "GET /search?q=<script>", "response": "200 OK with script"}
        remediation = "Encode output"
        source_tool = "ReflectedXssTester"
        worker_type = "input_validation"
        stage_name = "reflected_xss"

    class FakeTarget:
        domain = "test.com"

    report = tool._generate_individual_report(FakeVuln(), FakeTarget())
    assert report.startswith("## Title")
    assert "test.com" in report
    assert "4.7.1" in report
```

```bash
git add tests/test_reporting/test_integration.py
git commit -m "test(reporting): add integration test"
```
