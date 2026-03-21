# Phase 12: Exploit Chainer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the chain_worker Docker worker that links findings from phases 4-11 into 180 multi-stage attack chains with automated verification.

**Architecture:** Standard worker pattern (base_tool, tools/, pipeline, main.py) with a chain registry of 180 template classes. Each template has evaluate() (checks DB for preconditions) and execute() (runs chain steps). Four pipeline stages: collect findings, evaluate chains, execute viable chains, report results.

**Tech Stack:** Python 3.11+, aiohttp, OWASP ZAP API, pymetasploit3, Playwright, asyncio

**Design Doc:** `docs/plans/design/2026-03-20-phase12-exploit-chainer-design.md`

---

### Task 1: Core Data Models and Types

**Files:**
- Create: `workers/chain_worker/__init__.py`
- Create: `workers/chain_worker/models.py`
- Test: `tests/test_chain_worker_models.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_models.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from datetime import datetime


def test_chain_viability_enum():
    from workers.chain_worker.models import ChainViability
    assert ChainViability.VIABLE.value == "viable"
    assert ChainViability.PARTIAL.value == "partial"
    assert ChainViability.NOT_VIABLE.value == "not_viable"
    assert ChainViability.AWAITING_ACCOUNTS.value == "awaiting_accounts"


def test_chain_step_creation():
    from workers.chain_worker.models import ChainStep
    step = ChainStep(
        action="ssrf_probe",
        target="http://target.com/import",
        result="200 OK",
        timestamp=datetime.now().isoformat(),
        request={"method": "GET", "url": "http://target.com/import?url=http://169.254.169.254/"},
        response={"status": 200, "body": "iam-role-name"},
        screenshot_path="/evidence/step_1.png",
    )
    assert step.action == "ssrf_probe"
    assert step.request["method"] == "GET"
    assert step.screenshot_path == "/evidence/step_1.png"


def test_chain_step_optional_fields():
    from workers.chain_worker.models import ChainStep
    step = ChainStep(
        action="msf_check",
        target="192.168.1.1:22",
        result="vulnerable",
        timestamp=datetime.now().isoformat(),
    )
    assert step.request is None
    assert step.response is None
    assert step.screenshot_path is None


def test_chain_result_success():
    from workers.chain_worker.models import ChainResult, ChainStep
    step = ChainStep(
        action="test", target="t", result="ok",
        timestamp=datetime.now().isoformat(),
    )
    result = ChainResult(
        success=True,
        steps=[step],
        poc="curl http://target.com/exploit",
        chain_name="ssrf_cloud_compromise",
    )
    assert result.success is True
    assert len(result.steps) == 1
    assert result.poc.startswith("curl")


def test_chain_result_failure():
    from workers.chain_worker.models import ChainResult
    result = ChainResult(
        success=False, steps=[], poc=None,
        chain_name="info_to_access",
        failure_reason="No credentials found in config leak",
    )
    assert result.success is False
    assert result.failure_reason is not None


def test_evaluation_result():
    from workers.chain_worker.models import ChainViability, EvaluationResult
    er = EvaluationResult(
        viability=ChainViability.VIABLE,
        matched_preconditions=["ssrf_vuln_found", "cloud_asset_exists"],
        missing_preconditions=[],
        matched_findings={"ssrf_vuln_id": 42, "cloud_asset_id": 7},
    )
    assert er.viability == ChainViability.VIABLE
    assert len(er.matched_preconditions) == 2
    assert er.matched_findings["ssrf_vuln_id"] == 42


def test_evaluation_result_partial():
    from workers.chain_worker.models import ChainViability, EvaluationResult
    er = EvaluationResult(
        viability=ChainViability.PARTIAL,
        matched_preconditions=["ssrf_vuln_found"],
        missing_preconditions=["cloud_asset_exists"],
    )
    assert er.viability == ChainViability.PARTIAL
    assert "cloud_asset_exists" in er.missing_preconditions


def test_target_findings_grouping():
    from workers.chain_worker.models import TargetFindings
    tf = TargetFindings(
        target_id=1,
        vulnerabilities=[],
        assets=[],
        parameters=[],
        observations=[],
        locations=[],
        test_accounts=None,
    )
    assert tf.target_id == 1
    assert tf.test_accounts is None


def test_target_findings_with_accounts():
    from workers.chain_worker.models import TargetFindings, TestAccounts, AccountCreds
    accounts = TestAccounts(
        attacker=AccountCreds(username="attacker@test.com", password="pass1"),
        victim=AccountCreds(username="victim@test.com", password="pass2"),
    )
    tf = TargetFindings(
        target_id=1,
        vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[],
        test_accounts=accounts,
    )
    assert tf.test_accounts.attacker.username == "attacker@test.com"
    assert tf.test_accounts.victim.password == "pass2"


def test_target_findings_vulns_by_type():
    from workers.chain_worker.models import TargetFindings

    class FakeVuln:
        def __init__(self, title, severity, source_tool):
            self.title = title
            self.severity = severity
            self.source_tool = source_tool

    vulns = [
        FakeVuln("XSS in search", "high", "xss_finder"),
        FakeVuln("SSRF in import", "high", "ssrf_scanner"),
        FakeVuln("XSS in comment", "medium", "xss_finder"),
    ]
    tf = TargetFindings(
        target_id=1, vulnerabilities=vulns, assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    xss = tf.vulns_by_source("xss_finder")
    assert len(xss) == 2
    ssrf = tf.vulns_by_source("ssrf_scanner")
    assert len(ssrf) == 1


def test_target_findings_vulns_by_severity():
    from workers.chain_worker.models import TargetFindings

    class FakeVuln:
        def __init__(self, title, severity, source_tool):
            self.title = title
            self.severity = severity
            self.source_tool = source_tool

    vulns = [
        FakeVuln("Critical bug", "critical", "nmap"),
        FakeVuln("High bug", "high", "nmap"),
        FakeVuln("Low bug", "low", "nmap"),
    ]
    tf = TargetFindings(
        target_id=1, vulnerabilities=vulns, assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    crit = tf.vulns_by_severity("critical")
    assert len(crit) == 1
    high = tf.vulns_by_severity("high")
    assert len(high) == 1
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_models.py -v`
Expected: FAIL with ModuleNotFoundError

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/__init__.py
```

```python
# workers/chain_worker/models.py
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    screenshot_path: str | None = None


@dataclass
class ChainResult:
    success: bool
    steps: list[ChainStep]
    poc: str | None
    chain_name: str
    failure_reason: str | None = None


@dataclass
class EvaluationResult:
    viability: ChainViability
    matched_preconditions: list[str]
    missing_preconditions: list[str] = field(default_factory=list)
    matched_findings: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccountCreds:
    username: str
    password: str


@dataclass
class TestAccounts:
    attacker: AccountCreds
    victim: AccountCreds


@dataclass
class TargetFindings:
    target_id: int
    vulnerabilities: list[Any]
    assets: list[Any]
    parameters: list[Any]
    observations: list[Any]
    locations: list[Any]
    test_accounts: TestAccounts | None = None

    def vulns_by_source(self, source_tool: str) -> list[Any]:
        return [v for v in self.vulnerabilities if v.source_tool == source_tool]

    def vulns_by_severity(self, severity: str) -> list[Any]:
        return [v for v in self.vulnerabilities if v.severity == severity]

    def vulns_by_title_contains(self, substring: str) -> list[Any]:
        return [v for v in self.vulnerabilities
                if substring.lower() in v.title.lower()]

    def assets_by_type(self, asset_type: str) -> list[Any]:
        return [a for a in self.assets if a.asset_type == asset_type]

    def locations_by_service(self, service: str) -> list[Any]:
        return [loc for loc in self.locations if loc.service == service]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_models.py -v`
Expected: All 12 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/__init__.py workers/chain_worker/models.py tests/test_chain_worker_models.py
git commit -m "feat(chain-worker): add core data models and types"
```

---

### Task 2: Chain Registry with Decorator

**Files:**
- Create: `workers/chain_worker/registry.py`
- Test: `tests/test_chain_worker_registry.py`

**Step 1: Write the failing test**

```python
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
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
            )

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
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_registry.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/registry.py
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from workers.chain_worker.models import (
    ChainResult, EvaluationResult, TargetFindings,
)

_REGISTRY: dict[str, BaseChainTemplate] = {}


class ChainContext:
    def __init__(
        self,
        *,
        target_id: int,
        findings: TargetFindings,
        matched_findings: dict[str, Any],
        http_session: Any = None,
        zap_client: Any = None,
        msf_client: Any = None,
        scope_manager: Any = None,
        browser: Any = None,
        evidence_dir: str = "",
        step_delay_ms: int = 500,
        log: Any = None,
    ):
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
    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        pass

    @abstractmethod
    async def execute(self, context: ChainContext) -> ChainResult:
        pass


def register_chain(cls: type[BaseChainTemplate]) -> type[BaseChainTemplate]:
    if cls.name in _REGISTRY:
        raise ValueError(f"Chain '{cls.name}' already registered")
    _REGISTRY[cls.name] = cls()
    return cls


def get_registry() -> dict[str, BaseChainTemplate]:
    return _REGISTRY


def get_chains_by_category(category: str) -> list[BaseChainTemplate]:
    return [c for c in _REGISTRY.values() if c.category == category]


def clear_registry() -> None:
    _REGISTRY.clear()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_registry.py -v`
Expected: All 5 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/registry.py tests/test_chain_worker_registry.py
git commit -m "feat(chain-worker): add chain registry with decorator"
```

---

### Task 3: Concurrency Module

**Files:**
- Create: `workers/chain_worker/concurrency.py`
- Test: `tests/test_chain_worker_concurrency.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_concurrency.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.concurrency import WeightClass, get_semaphore


def test_weight_class_values():
    assert WeightClass.HEAVY.value == "heavy"
    assert WeightClass.MEDIUM.value == "medium"
    assert WeightClass.LIGHT.value == "light"


@pytest.mark.anyio
async def test_heavy_semaphore_acquires():
    sem = get_semaphore(WeightClass.HEAVY)
    async with sem:
        pass


@pytest.mark.anyio
async def test_light_semaphore_allows_concurrency():
    import asyncio
    sem = get_semaphore(WeightClass.LIGHT)
    acquired = 0

    async def acquire():
        nonlocal acquired
        async with sem:
            acquired += 1
            await asyncio.sleep(0.01)

    await asyncio.gather(*[acquire() for _ in range(4)])
    assert acquired == 4
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_concurrency.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/concurrency.py
from __future__ import annotations

import asyncio
import os
from enum import Enum

_semaphores: dict[str, asyncio.BoundedSemaphore] = {}


class WeightClass(Enum):
    HEAVY = "heavy"
    MEDIUM = "medium"
    LIGHT = "light"


_DEFAULTS = {
    WeightClass.HEAVY: 1,
    WeightClass.MEDIUM: 2,
    WeightClass.LIGHT: 4,
}

_ENV_KEYS = {
    WeightClass.HEAVY: "HEAVY_CONCURRENCY",
    WeightClass.MEDIUM: "MEDIUM_CONCURRENCY",
    WeightClass.LIGHT: "LIGHT_CONCURRENCY",
}


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    if weight.value not in _semaphores:
        cap = int(os.environ.get(_ENV_KEYS[weight], _DEFAULTS[weight]))
        _semaphores[weight.value] = asyncio.BoundedSemaphore(cap)
    return _semaphores[weight.value]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_concurrency.py -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/concurrency.py tests/test_chain_worker_concurrency.py
git commit -m "feat(chain-worker): add semaphore concurrency control"
```

---

### Task 4: Base Tool with DB Helpers

**Files:**
- Create: `workers/chain_worker/base_tool.py`
- Test: `tests/test_chain_worker_base_tool.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_base_tool.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass


def test_base_is_abstract():
    import inspect
    assert inspect.isabstract(ChainTestTool)


def test_constants():
    from workers.chain_worker.base_tool import TOOL_TIMEOUT, COOLDOWN_HOURS
    assert TOOL_TIMEOUT == 600
    assert COOLDOWN_HOURS == 24


@pytest.mark.anyio
async def test_take_screenshot_no_browser():
    from workers.chain_worker.base_tool import take_screenshot
    path = await take_screenshot(
        browser=None, url="http://example.com", output_path="/tmp/test.png",
    )
    assert path is None


@pytest.mark.anyio
async def test_step_delay():
    import time
    from workers.chain_worker.base_tool import step_delay
    os.environ["CHAIN_STEP_DELAY_MS"] = "50"
    start = time.monotonic()
    await step_delay()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.04
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_base_tool.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/base_tool.py
from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import (
    Alert, JobState, Observation, Vulnerability,
)
from lib_webbh.messaging import push_task
from sqlalchemy import select

from workers.chain_worker.concurrency import WeightClass

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))
CHAIN_STEP_DELAY_MS = int(os.environ.get("CHAIN_STEP_DELAY_MS", "500"))

logger = setup_logger("chain_worker")


class ChainTestTool(ABC):
    name: str
    weight_class: WeightClass

    @abstractmethod
    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        pass

    async def run_subprocess(
        self, cmd: list[str], timeout: int = TOOL_TIMEOUT,
    ) -> str:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise
        return stdout.decode(errors="replace")

    async def check_cooldown(self, target_id: int, container_name: str) -> bool:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
                JobState.last_tool_executed == self.name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row and row.last_seen:
                elapsed = (datetime.now(timezone.utc) - row.last_seen).total_seconds()
                return elapsed < COOLDOWN_HOURS * 3600
        return False

    async def update_tool_state(self, target_id: int, container_name: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.last_tool_executed = self.name
                row.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _save_vulnerability(
        self, target_id: int, asset_id: int | None, severity: str,
        title: str, description: str, poc: str | None = None,
        source_tool: str | None = None,
    ) -> int:
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id, asset_id=asset_id, severity=severity,
                title=title, description=description, poc=poc,
                source_tool=source_tool or f"chain:{self.name}",
            )
            session.add(vuln)
            await session.flush()
            vuln_id = vuln.id

            if severity in ("critical", "high"):
                alert = Alert(
                    target_id=target_id, vulnerability_id=vuln_id,
                    alert_type=severity, message=f"[CHAIN] {title}", is_read=False,
                )
                session.add(alert)
                await session.commit()
                await push_task(f"events:{target_id}", {
                    "event": "critical_alert", "alert_type": severity,
                    "title": title, "vulnerability_id": vuln_id,
                })
            else:
                await session.commit()
            return vuln_id

    async def _save_observation(self, asset_id: int, tech_stack: dict[str, Any]) -> int:
        async with get_session() as session:
            obs = Observation(asset_id=asset_id, tech_stack=tech_stack)
            session.add(obs)
            await session.commit()
            return obs.id

    async def _create_action_required_alert(self, target_id: int, message: str) -> int:
        async with get_session() as session:
            alert = Alert(
                target_id=target_id, alert_type="action_required",
                message=message, is_read=False,
            )
            session.add(alert)
            await session.commit()
            await push_task(f"events:{target_id}", {
                "event": "action_required", "message": message,
            })
            return alert.id


async def take_screenshot(browser: Any, url: str, output_path: str) -> str | None:
    if browser is None:
        return None
    try:
        page = await browser.new_page()
        await page.goto(url, wait_until="networkidle", timeout=15000)
        await page.screenshot(path=output_path, full_page=True)
        await page.close()
        return output_path
    except Exception:
        return None


async def render_terminal_screenshot(text: str, output_path: str) -> str | None:
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            html = (
                f"<html><body style='background:#1e1e1e;color:#d4d4d4;"
                f"font-family:monospace;padding:20px;white-space:pre-wrap;'>"
                f"{text}</body></html>"
            )
            await page.set_content(html)
            await page.screenshot(path=output_path)
            await browser.close()
            return output_path
    except Exception:
        return None


async def step_delay() -> None:
    delay_ms = int(os.environ.get("CHAIN_STEP_DELAY_MS", "500"))
    await asyncio.sleep(delay_ms / 1000)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_base_tool.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/base_tool.py tests/test_chain_worker_base_tool.py
git commit -m "feat(chain-worker): add base tool with DB helpers and screenshot utils"
```

---

### Task 5: FindingsCollector Tool

**Files:**
- Create: `workers/chain_worker/tools/__init__.py`
- Create: `workers/chain_worker/tools/findings_collector.py`
- Test: `tests/test_chain_worker_findings_collector.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_findings_collector.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import json
import pytest
from workers.chain_worker.tools.findings_collector import FindingsCollector, _load_test_accounts
from workers.chain_worker.concurrency import WeightClass


def test_tool_attributes():
    tool = FindingsCollector()
    assert tool.name == "findings_collector"
    assert tool.weight_class == WeightClass.LIGHT


def test_load_test_accounts_from_profile(tmp_path):
    profile = {
        "in_scope_domains": ["example.com"],
        "test_accounts": {
            "attacker": {"username": "atk@test.com", "password": "pass1"},
            "victim": {"username": "vic@test.com", "password": "pass2"},
        },
    }
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile))
    accounts = _load_test_accounts(str(profile_path))
    assert accounts is not None
    assert accounts.attacker.username == "atk@test.com"
    assert accounts.victim.password == "pass2"


def test_load_test_accounts_missing_key(tmp_path):
    profile = {"in_scope_domains": ["example.com"]}
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile))
    accounts = _load_test_accounts(str(profile_path))
    assert accounts is None


def test_load_test_accounts_missing_file():
    accounts = _load_test_accounts("/nonexistent/profile.json")
    assert accounts is None
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_findings_collector.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/tools/__init__.py
```

```python
# workers/chain_worker/tools/findings_collector.py
from __future__ import annotations

import json
import os
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import Asset, Location, Observation, Parameter, Vulnerability
from sqlalchemy import select

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import AccountCreds, TargetFindings, TestAccounts

logger = setup_logger("findings_collector")


def _load_test_accounts(profile_path: str) -> TestAccounts | None:
    try:
        with open(profile_path) as f:
            profile = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    accounts = profile.get("test_accounts")
    if not accounts:
        return None
    try:
        return TestAccounts(
            attacker=AccountCreds(
                username=accounts["attacker"]["username"],
                password=accounts["attacker"]["password"],
            ),
            victim=AccountCreds(
                username=accounts["victim"]["username"],
                password=accounts["victim"]["password"],
            ),
        )
    except (KeyError, TypeError):
        return None


class FindingsCollector(ChainTestTool):
    name = "findings_collector"
    weight_class = WeightClass.LIGHT

    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        log = logger.bind(target_id=target_id)
        async with get_session() as session:
            vulns = list((await session.execute(
                select(Vulnerability).where(Vulnerability.target_id == target_id)
            )).scalars().all())
            assets = list((await session.execute(
                select(Asset).where(Asset.target_id == target_id)
            )).scalars().all())
            asset_ids = [a.id for a in assets]
            if asset_ids:
                params = list((await session.execute(
                    select(Parameter).where(Parameter.asset_id.in_(asset_ids))
                )).scalars().all())
                observations = list((await session.execute(
                    select(Observation).where(Observation.asset_id.in_(asset_ids))
                )).scalars().all())
                locations = list((await session.execute(
                    select(Location).where(Location.asset_id.in_(asset_ids))
                )).scalars().all())
            else:
                params, observations, locations = [], [], []

        profile_path = os.path.join("shared", "config", str(target_id), "profile.json")
        test_accounts = _load_test_accounts(profile_path)

        findings = TargetFindings(
            target_id=target_id, vulnerabilities=vulns, assets=assets,
            parameters=params, observations=observations, locations=locations,
            test_accounts=test_accounts,
        )
        log.info("Findings collected", extra={
            "vulns": len(vulns), "assets": len(assets), "params": len(params),
            "observations": len(observations), "locations": len(locations),
            "has_test_accounts": test_accounts is not None,
        })
        kwargs["_findings"] = findings
        return {
            "vulns": len(vulns), "assets": len(assets), "params": len(params),
            "observations": len(observations), "locations": len(locations),
        }
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_findings_collector.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/tools/__init__.py workers/chain_worker/tools/findings_collector.py tests/test_chain_worker_findings_collector.py
git commit -m "feat(chain-worker): add FindingsCollector for stage 1"
```

---

### Task 6: ChainEvaluator Tool

**Files:**
- Create: `workers/chain_worker/tools/chain_evaluator.py`
- Test: `tests/test_chain_worker_evaluator.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_evaluator.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainViability, EvaluationResult, ChainResult, TargetFindings
from workers.chain_worker.registry import BaseChainTemplate, register_chain, clear_registry


def test_tool_attributes():
    tool = ChainEvaluator()
    assert tool.name == "chain_evaluator"
    assert tool.weight_class == WeightClass.LIGHT


@pytest.mark.anyio
async def test_evaluate_buckets():
    clear_registry()

    @register_chain
    class V(BaseChainTemplate):
        name = "v1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            return ChainResult(success=True, steps=[], poc="t", chain_name=self.name)

    @register_chain
    class P(BaseChainTemplate):
        name = "p1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["half"], missing_preconditions=["other"])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    @register_chain
    class N(BaseChainTemplate):
        name = "n1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[])
        async def execute(self, context):
            return ChainResult(success=False, steps=[], poc=None, chain_name=self.name)

    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    evaluator = ChainEvaluator()
    buckets = await evaluator.evaluate_all(findings)
    assert len(buckets["viable"]) == 1
    assert len(buckets["partial"]) == 1
    assert len(buckets["not_viable"]) == 1
    clear_registry()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_evaluator.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/tools/chain_evaluator.py
from __future__ import annotations

from typing import Any

from lib_webbh import setup_logger

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainViability, EvaluationResult, TargetFindings
from workers.chain_worker.registry import get_registry

logger = setup_logger("chain_evaluator")


class ChainEvaluator(ChainTestTool):
    name = "chain_evaluator"
    weight_class = WeightClass.LIGHT

    async def evaluate_all(
        self, findings: TargetFindings,
    ) -> dict[str, list[tuple[str, EvaluationResult]]]:
        registry = get_registry()
        buckets: dict[str, list[tuple[str, EvaluationResult]]] = {
            "viable": [], "awaiting_accounts": [], "partial": [], "not_viable": [],
        }
        for name, chain in registry.items():
            try:
                result = await chain.evaluate(findings)
            except Exception as exc:
                logger.warning("Chain evaluate failed", extra={"chain": name, "error": str(exc)})
                continue
            buckets[result.viability.value].append((name, result))

        logger.info("Evaluation complete", extra={
            "target_id": findings.target_id,
            "viable": len(buckets["viable"]),
            "awaiting_accounts": len(buckets["awaiting_accounts"]),
            "partial": len(buckets["partial"]),
            "not_viable": len(buckets["not_viable"]),
        })
        return buckets

    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        findings: TargetFindings = kwargs["_findings"]
        buckets = await self.evaluate_all(findings)
        kwargs["_buckets"] = buckets
        return {
            "viable": len(buckets["viable"]),
            "awaiting_accounts": len(buckets["awaiting_accounts"]),
            "partial": len(buckets["partial"]),
            "not_viable": len(buckets["not_viable"]),
        }
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_evaluator.py -v`
Expected: All 2 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/tools/chain_evaluator.py tests/test_chain_worker_evaluator.py
git commit -m "feat(chain-worker): add ChainEvaluator for stage 2"
```

---

### Task 7: ChainExecutor Tool

**Files:**
- Create: `workers/chain_worker/tools/chain_executor.py`
- Test: `tests/test_chain_worker_executor.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_executor.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ["CHAIN_STEP_DELAY_MS"] = "1"

import pytest
from datetime import datetime
from workers.chain_worker.tools.chain_executor import ChainExecutor
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainViability, ChainResult, ChainStep, EvaluationResult, TargetFindings
from workers.chain_worker.registry import BaseChainTemplate, ChainContext, register_chain, clear_registry


def test_tool_attributes():
    tool = ChainExecutor()
    assert tool.name == "chain_executor"
    assert tool.weight_class == WeightClass.HEAVY


@pytest.mark.anyio
async def test_run_viable_chains(tmp_path):
    clear_registry()

    @register_chain
    class S(BaseChainTemplate):
        name = "s1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            return ChainResult(
                success=True,
                steps=[ChainStep(action="a", target="t", result="ok", timestamp=datetime.now().isoformat())],
                poc="curl exploit", chain_name=self.name,
            )

    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    viable = [("s1", EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"], matched_findings={"v": 1}))]
    executor = ChainExecutor()
    results = await executor.run_chains(
        viable_chains=viable, findings=findings, target_id=1,
        scope_manager=None, evidence_dir=str(tmp_path),
    )
    assert len(results) == 1
    assert results[0].success is True
    clear_registry()


@pytest.mark.anyio
async def test_failed_chain_continues(tmp_path):
    clear_registry()

    @register_chain
    class F(BaseChainTemplate):
        name = "f1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            raise RuntimeError("broke")

    @register_chain
    class O(BaseChainTemplate):
        name = "o1"
        category = "t"
        severity_on_success = "critical"
        requires_accounts = False
        async def evaluate(self, findings):
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])
        async def execute(self, context):
            return ChainResult(success=True, steps=[], poc="ok", chain_name=self.name)

    findings = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    viable = [
        ("f1", EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])),
        ("o1", EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ok"])),
    ]
    executor = ChainExecutor()
    results = await executor.run_chains(
        viable_chains=viable, findings=findings, target_id=1,
        scope_manager=None, evidence_dir=str(tmp_path),
    )
    assert len(results) == 2
    assert results[0].success is False
    assert results[1].success is True
    clear_registry()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_executor.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/tools/chain_executor.py
from __future__ import annotations

import os
from typing import Any

from lib_webbh import setup_logger

from workers.chain_worker.base_tool import ChainTestTool, step_delay
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainResult, EvaluationResult, TargetFindings
from workers.chain_worker.registry import ChainContext, get_registry

logger = setup_logger("chain_executor")


class ChainExecutor(ChainTestTool):
    name = "chain_executor"
    weight_class = WeightClass.HEAVY

    async def run_chains(
        self, viable_chains: list[tuple[str, EvaluationResult]],
        findings: TargetFindings, target_id: int, scope_manager: Any,
        evidence_dir: str, http_session: Any = None, zap_client: Any = None,
        msf_client: Any = None, browser: Any = None,
    ) -> list[ChainResult]:
        registry = get_registry()
        results: list[ChainResult] = []

        for chain_name, eval_result in viable_chains:
            chain = registry.get(chain_name)
            if chain is None:
                continue
            log = logger.bind(target_id=target_id, chain=chain_name)
            log.info("Executing chain")
            chain_evidence_dir = os.path.join(evidence_dir, chain_name)
            os.makedirs(chain_evidence_dir, exist_ok=True)

            context = ChainContext(
                target_id=target_id, findings=findings,
                matched_findings=eval_result.matched_findings,
                http_session=http_session, zap_client=zap_client,
                msf_client=msf_client, scope_manager=scope_manager,
                browser=browser, evidence_dir=chain_evidence_dir, log=log,
            )
            try:
                result = await chain.execute(context)
                results.append(result)
                log.info("Chain completed", extra={"success": result.success, "steps": len(result.steps)})
            except Exception as exc:
                log.error("Chain failed", extra={"error": str(exc)})
                results.append(ChainResult(
                    success=False, steps=[], poc=None,
                    chain_name=chain_name, failure_reason=str(exc),
                ))
            await step_delay()
        return results

    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        findings: TargetFindings = kwargs["_findings"]
        buckets = kwargs["_buckets"]
        viable = buckets.get("viable", [])
        evidence_dir = os.path.join("shared", "config", str(target_id), "chain_evidence")
        results = await self.run_chains(
            viable_chains=viable, findings=findings, target_id=target_id,
            scope_manager=scope_manager, evidence_dir=evidence_dir,
            http_session=kwargs.get("_http_session"),
            zap_client=kwargs.get("_zap_client"),
            msf_client=kwargs.get("_msf_client"),
            browser=kwargs.get("_browser"),
        )
        kwargs["_chain_results"] = results
        succeeded = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        return {"executed": len(results), "succeeded": len(succeeded), "failed": len(failed)}
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_executor.py -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/tools/chain_executor.py tests/test_chain_worker_executor.py
git commit -m "feat(chain-worker): add ChainExecutor for stage 3"
```

---

### Task 8: ChainReporter Tool

**Files:**
- Create: `workers/chain_worker/tools/chain_reporter.py`
- Test: `tests/test_chain_worker_reporter.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_reporter.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from datetime import datetime
from workers.chain_worker.tools.chain_reporter import ChainReporter
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainResult, ChainStep


def test_tool_attributes():
    tool = ChainReporter()
    assert tool.name == "chain_reporter"
    assert tool.weight_class == WeightClass.LIGHT


def test_build_description():
    tool = ChainReporter()
    steps = [
        ChainStep(action="ssrf_probe", target="import_url", result="200 OK", timestamp=datetime.now().isoformat()),
        ChainStep(action="imds_query", target="169.254.169.254", result="iam_role_found", timestamp=datetime.now().isoformat()),
    ]
    result = ChainResult(success=True, steps=steps, poc="curl http://target.com/import?url=http://169.254.169.254/", chain_name="ssrf_cloud")
    desc = tool._build_description(result)
    assert "Step 1:" in desc
    assert "Step 2:" in desc
    assert "ssrf_probe" in desc


def test_build_tech_stack_json():
    tool = ChainReporter()
    steps = [
        ChainStep(action="test", target="t", result="ok", timestamp="2026-03-20T14:00:00", screenshot_path="/evidence/step_1.png"),
    ]
    result = ChainResult(success=True, steps=steps, poc="test", chain_name="test_chain")
    tech = tool._build_tech_stack(result, "test_category")
    assert tech["chain_type"] == "test_chain"
    assert tech["chain_category"] == "test_category"
    assert tech["total_steps"] == 1
    assert tech["steps"][0]["screenshot"] == "/evidence/step_1.png"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_reporter.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/tools/chain_reporter.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from lib_webbh import setup_logger
from lib_webbh.messaging import push_task

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import WeightClass
from workers.chain_worker.models import ChainResult, TargetFindings
from workers.chain_worker.registry import get_registry

logger = setup_logger("chain_reporter")


class ChainReporter(ChainTestTool):
    name = "chain_reporter"
    weight_class = WeightClass.LIGHT

    def _build_description(self, result: ChainResult) -> str:
        lines = [f"Multi-stage attack chain: {result.chain_name}", ""]
        for i, step in enumerate(result.steps, 1):
            lines.append(f"Step {i}: [{step.action}] Target: {step.target} -> Result: {step.result}")
        if result.poc:
            lines.extend(["", f"PoC: {result.poc}"])
        return "\n".join(lines)

    def _build_tech_stack(self, result: ChainResult, category: str) -> dict[str, Any]:
        steps_json = []
        for step in result.steps:
            entry: dict[str, Any] = {"action": step.action, "target": step.target, "result": step.result}
            if step.screenshot_path:
                entry["screenshot"] = step.screenshot_path
            steps_json.append(entry)
        return {
            "chain_type": result.chain_name,
            "chain_category": category,
            "steps": steps_json,
            "total_steps": len(result.steps),
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def report(self, results: list[ChainResult], target_id: int, findings: TargetFindings) -> dict[str, int]:
        registry = get_registry()
        reported = 0
        for result in results:
            if not result.success:
                continue
            chain = registry.get(result.chain_name)
            if chain is None:
                continue
            primary_asset_id = findings.assets[0].id if findings.assets else None
            title = f"CHAINED: {result.chain_name.replace('_', ' ').title()}"
            vuln_id = await self._save_vulnerability(
                target_id=target_id, asset_id=primary_asset_id,
                severity=chain.severity_on_success, title=title,
                description=self._build_description(result), poc=result.poc,
                source_tool=f"chain:{result.chain_name}",
            )
            if primary_asset_id:
                tech_stack = self._build_tech_stack(result, chain.category)
                await self._save_observation(primary_asset_id, tech_stack)
            await push_task(f"events:{target_id}", {
                "event": "chain_success", "chain": result.chain_name,
                "severity": chain.severity_on_success, "steps": len(result.steps),
                "target_id": target_id, "vulnerability_id": vuln_id,
            })
            reported += 1
        return {"reported": reported}

    async def execute(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str, **kwargs: Any,
    ) -> dict[str, Any]:
        results: list[ChainResult] = kwargs.get("_chain_results", [])
        findings: TargetFindings = kwargs["_findings"]
        return await self.report(results=results, target_id=target_id, findings=findings)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_reporter.py -v`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/tools/chain_reporter.py tests/test_chain_worker_reporter.py
git commit -m "feat(chain-worker): add ChainReporter for stage 4"
```

---

### Task 9: Pipeline Orchestration

**Files:**
- Create: `workers/chain_worker/pipeline.py`
- Test: `tests/test_chain_worker_pipeline.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_pipeline.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.pipeline import STAGES, Pipeline


def test_pipeline_has_four_stages():
    assert len(STAGES) == 4


def test_stage_names():
    names = [s.name for s in STAGES]
    assert names == ["data_collection", "chain_evaluation", "chain_execution", "reporting"]


def test_stage_tool_classes():
    from workers.chain_worker.tools.findings_collector import FindingsCollector
    from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
    from workers.chain_worker.tools.chain_executor import ChainExecutor
    from workers.chain_worker.tools.chain_reporter import ChainReporter
    assert STAGES[0].tool_classes == [FindingsCollector]
    assert STAGES[1].tool_classes == [ChainEvaluator]
    assert STAGES[2].tool_classes == [ChainExecutor]
    assert STAGES[3].tool_classes == [ChainReporter]


def test_pipeline_init():
    pipeline = Pipeline()
    assert pipeline is not None
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_pipeline.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# workers/chain_worker/pipeline.py
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState
from lib_webbh.messaging import push_task
from sqlalchemy import select

from workers.chain_worker.base_tool import ChainTestTool
from workers.chain_worker.concurrency import get_semaphore
from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
from workers.chain_worker.tools.chain_executor import ChainExecutor
from workers.chain_worker.tools.chain_reporter import ChainReporter
from workers.chain_worker.tools.findings_collector import FindingsCollector

logger = setup_logger("chain_pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[ChainTestTool]]


STAGES: list[Stage] = [
    Stage("data_collection", [FindingsCollector]),
    Stage("chain_evaluation", [ChainEvaluator]),
    Stage("chain_execution", [ChainExecutor]),
    Stage("reporting", [ChainReporter]),
]

STAGE_INDEX: dict[str, int] = {s.name: i for i, s in enumerate(STAGES)}


class Pipeline:
    async def run(
        self, target: Any, scope_manager: Any,
        target_id: int, container_name: str,
    ) -> None:
        log = logger.bind(target_id=target_id)
        start_index = await self._get_resume_index(target_id, container_name)
        kwargs: dict[str, Any] = {}

        for i in range(start_index, len(STAGES)):
            stage = STAGES[i]
            log.info("Starting stage", extra={"stage": stage.name})
            tools = [cls() for cls in stage.tool_classes]
            tasks = []
            for tool in tools:
                sem = get_semaphore(tool.weight_class)

                async def _run(t: ChainTestTool = tool, s: Any = sem) -> dict:
                    async with s:
                        return await t.execute(
                            target=target, scope_manager=scope_manager,
                            target_id=target_id, container_name=container_name,
                            **kwargs,
                        )

                tasks.append(_run())

            results = await asyncio.gather(*tasks, return_exceptions=True)
            stats: dict[str, Any] = {}
            for r in results:
                if isinstance(r, Exception):
                    log.error("Tool failed", extra={"stage": stage.name, "error": str(r)})
                elif isinstance(r, dict):
                    stats.update(r)

            await self._update_phase(target_id, container_name, stage.name)
            await push_task(f"events:{target_id}", {
                "event": "stage_complete", "stage": stage.name, "stats": stats,
            })
            log.info("Stage complete", extra={"stage": stage.name, "stats": stats})

        await self._mark_completed(target_id, container_name)
        await push_task(f"events:{target_id}", {"event": "pipeline_complete", "worker": "chain_worker"})

    async def _get_resume_index(self, target_id: int, container_name: str) -> int:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row and row.current_phase and row.status != "COMPLETED":
                idx = STAGE_INDEX.get(row.current_phase, -1)
                return idx + 1
        return 0

    async def _update_phase(self, target_id: int, container_name: str, phase: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.current_phase = phase
                row.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _mark_completed(self, target_id: int, container_name: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row:
                row.status = "COMPLETED"
                row.last_seen = datetime.now(timezone.utc)
                await session.commit()
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_pipeline.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/pipeline.py tests/test_chain_worker_pipeline.py
git commit -m "feat(chain-worker): add 4-stage pipeline with checkpointing"
```

---

### Task 10: Main Entry Point

**Files:**
- Create: `workers/chain_worker/main.py`
- Create: `workers/chain_worker/chains/__init__.py`
- Test: `tests/test_chain_worker_main.py`

**Step 1: Write the failing test**

```python
# tests/test_chain_worker_main.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest


def test_get_container_name_default(monkeypatch):
    monkeypatch.delenv("HOSTNAME", raising=False)
    from workers.chain_worker.main import get_container_name
    assert get_container_name() == "chain-worker-unknown"


def test_get_container_name_from_env(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "webbh-chain-worker-1")
    from workers.chain_worker.main import get_container_name
    assert get_container_name() == "webbh-chain-worker-1"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_chain_worker_main.py -v`
Expected: FAIL

**Step 3: Create chains package and main.py**

```python
# workers/chain_worker/chains/__init__.py
```

```python
# workers/chain_worker/main.py
from __future__ import annotations

import asyncio
import os
import subprocess
from datetime import datetime, timezone
from typing import Any

from lib_webbh import get_session, setup_logger
from lib_webbh.database import JobState, Target
from lib_webbh.messaging import listen_queue
from lib_webbh.scope import ScopeManager
from sqlalchemy import select

from workers.chain_worker.pipeline import Pipeline

# Import chains package so templates register via decorator
import workers.chain_worker.chains  # noqa: F401

logger = setup_logger("chain_worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
MSFRPC_PASS = os.environ.get("MSFRPC_PASS", "msf_internal")
MSFRPC_PORT = int(os.environ.get("MSFRPC_PORT", "55553"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "chain-worker-unknown")


async def _start_zap() -> subprocess.Popen | None:
    try:
        proc = subprocess.Popen(
            ["zap.sh", "-daemon", "-port", str(ZAP_PORT), "-config", "api.disablekey=true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.info("ZAP daemon started", extra={"port": ZAP_PORT})
        return proc
    except FileNotFoundError:
        logger.warning("ZAP not found, skipping")
        return None


async def _wait_for_zap(retries: int = 30, delay: float = 2.0) -> bool:
    import aiohttp
    for _ in range(retries):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"http://127.0.0.1:{ZAP_PORT}/JSON/core/view/version/") as resp:
                    if resp.status == 200:
                        logger.info("ZAP ready")
                        return True
        except Exception:
            pass
        await asyncio.sleep(delay)
    logger.error("ZAP failed to start")
    return False


async def _start_msfrpcd() -> subprocess.Popen | None:
    try:
        proc = subprocess.Popen(
            ["msfrpcd", "-P", MSFRPC_PASS, "-p", str(MSFRPC_PORT), "-S", "-f"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.info("msfrpcd started", extra={"port": MSFRPC_PORT})
        return proc
    except FileNotFoundError:
        logger.warning("msfrpcd not found, skipping")
        return None


async def _wait_for_msfrpcd(retries: int = 30, delay: float = 2.0) -> bool:
    for _ in range(retries):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            MsfRpcClient(MSFRPC_PASS, port=MSFRPC_PORT, ssl=True)
            logger.info("msfrpcd ready")
            return True
        except Exception:
            pass
        await asyncio.sleep(delay)
    logger.error("msfrpcd failed to start")
    return False


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    while True:
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                row = (await session.execute(stmt)).scalar_one_or_none()
                if row:
                    row.last_seen = datetime.now(timezone.utc)
                    await session.commit()
        except Exception:
            pass
        await asyncio.sleep(HEARTBEAT_INTERVAL)


async def handle_message(msg_id: str, data: dict[str, Any]) -> None:
    target_id = data["target_id"]
    container_name = get_container_name()
    log = logger.bind(target_id=target_id, container=container_name)
    log.info("Received chain task", extra={"trigger": data.get("trigger_phase")})

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            log.error("Target not found")
            return
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        job = (await session.execute(stmt)).scalar_one_or_none()
        if job is None:
            job = JobState(
                target_id=target_id, container_name=container_name,
                status="RUNNING", current_phase="init",
                last_seen=datetime.now(timezone.utc),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.current_phase = "init"
            job.last_seen = datetime.now(timezone.utc)
        await session.commit()

    scope_manager = ScopeManager(target.target_profile or {})
    heartbeat = asyncio.create_task(_heartbeat_loop(target_id, container_name))

    try:
        pipeline = Pipeline()
        await pipeline.run(
            target=target, scope_manager=scope_manager,
            target_id=target_id, container_name=container_name,
        )
    except Exception as exc:
        log.error("Pipeline failed", extra={"error": str(exc)})
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            job = (await session.execute(stmt)).scalar_one_or_none()
            if job:
                job.status = "FAILED"
                await session.commit()
    finally:
        heartbeat.cancel()
        try:
            await heartbeat
        except asyncio.CancelledError:
            pass


async def main() -> None:
    logger.info("Chain worker starting")
    zap_proc = await _start_zap()
    msf_proc = await _start_msfrpcd()
    if zap_proc:
        await _wait_for_zap()
    if msf_proc:
        await _wait_for_msfrpcd()
    container_name = get_container_name()
    logger.info("Listening for tasks", extra={"consumer": container_name})
    await listen_queue(
        queue="chain_queue", group="chain_group",
        consumer=container_name, callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_chain_worker_main.py -v`
Expected: All 2 tests PASS

**Step 5: Commit**

```bash
git add workers/chain_worker/main.py workers/chain_worker/chains/__init__.py tests/test_chain_worker_main.py
git commit -m "feat(chain-worker): add main entry point with ZAP + MSF lifecycle"
```

---

### Task 11: Dockerfile and Docker Compose

**Files:**
- Create: `docker/Dockerfile.chain`
- Modify: `docker-compose.yml`

**Step 1: Create Dockerfile**

```dockerfile
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    curl ca-certificates unzip \
    zaproxy \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages playwright \
    && playwright install chromium --with-deps

COPY shared/lib_webbh /app/shared/lib_webbh
RUN pip3 install --break-system-packages -e /app/shared/lib_webbh

RUN pip3 install --break-system-packages \
    aiohttp \
    pymetasploit3 \
    pyyaml \
    python-owasp-zap-v2.4

COPY workers/chain_worker /app/workers/chain_worker

WORKDIR /app

CMD ["python3", "-m", "workers.chain_worker.main"]
```

**Step 2: Add docker-compose entry for chain-worker service**

Add after the network-worker service block in `docker-compose.yml`:

```yaml
  chain-worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.chain
    container_name: webbh-chain-worker
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      DB_HOST: postgres
      DB_PORT: "5432"
      DB_NAME: ${DB_NAME:-webbh}
      DB_USER: ${DB_USER:-webbh_admin}
      DB_PASS: ${DB_PASS:-changeme}
      REDIS_HOST: redis
      REDIS_PORT: "6379"
      MSFRPC_PASS: msf_internal
      CHAIN_STEP_DELAY_MS: "500"
      TOOL_TIMEOUT: "600"
      COOLDOWN_HOURS: "24"
    volumes:
      - ./shared/config:/app/shared/config
    mem_limit: 4g
```

**Step 3: Commit**

```bash
git add docker/Dockerfile.chain docker-compose.yml
git commit -m "feat(chain-worker): add Dockerfile and docker-compose entry"
```

---

### Tasks 12-20: Chain Template Implementation (180 Templates)

Each task creates one category module under `workers/chain_worker/chains/` plus a test file. Every chain template class follows this pattern:

```python
@register_chain
class DescriptiveClassName(BaseChainTemplate):
    name = "snake_case_unique_name"
    category = "category_name"              # matches category module
    severity_on_success = "critical"
    requires_accounts = False               # True if chain modifies state

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        # Search findings for preconditions
        matching = findings.vulns_by_title_contains("keyword")
        if not matching:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["keyword_vulnerability"],
            )
        if self.requires_accounts and findings.test_accounts is None:
            return EvaluationResult(
                viability=ChainViability.AWAITING_ACCOUNTS,
                matched_preconditions=["keyword_found"],
                missing_preconditions=["test_accounts"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["keyword_found"],
            matched_findings={"vuln_id": matching[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        from workers.chain_worker.base_tool import step_delay, take_screenshot
        steps = []
        ts = datetime.now(timezone.utc).isoformat()
        # Step 1: probe/verify
        # Step 2: exploit/chain
        # Step N: ...
        # On any step failure: return ChainResult(success=False, ...)
        return ChainResult(success=True, steps=steps, poc="...", chain_name=self.name)
```

**Test pattern for each category:**

```python
def test_chain_count():
    from workers.chain_worker.registry import get_chains_by_category
    chains = get_chains_by_category("category_name")
    assert len(chains) == EXPECTED_COUNT

def test_chain_attributes():
    from workers.chain_worker.registry import get_chains_by_category
    for chain in get_chains_by_category("category_name"):
        assert chain.name
        assert chain.category == "category_name"
        assert chain.severity_on_success in ("critical", "high")

@pytest.mark.anyio
async def test_all_not_viable_with_empty_findings():
    from workers.chain_worker.registry import get_chains_by_category
    from workers.chain_worker.models import TargetFindings, ChainViability
    empty = TargetFindings(
        target_id=1, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    for chain in get_chains_by_category("category_name"):
        result = await chain.evaluate(empty)
        assert result.viability in (ChainViability.NOT_VIABLE, ChainViability.PARTIAL)
```

**Evaluate condition reference for each chain:**

#### Task 12: Auth/Session (22 chains) — `chains/auth_session.py`

| # | Chain name | Evaluates for |
|---|---|---|
| 1 | info_to_access | vuln "info" or "config" + location service ssh/mysql/ftp |
| 2 | idor_account_takeover | vuln "IDOR" + requires_accounts |
| 3 | oauth_dirty_dancing | vuln "OAuth" or "redirect" + param "state"/"code" |
| 4 | twofa_bypass_ato | vuln "2FA" or "OTP" + requires_accounts |
| 5 | mass_assignment_privesc | vuln "mass assignment" + requires_accounts |
| 6 | sso_saml_impersonation | vuln "SAML" or "SSO" |
| 7 | session_token_referer_leak | param with "session"/"token" in URL |
| 8 | timing_user_enum_bruteforce | vuln "user enum" or obs with login endpoint |
| 9 | jwt_weakness_auth_bypass | vuln "JWT" |
| 10 | password_reset_token_prediction | vuln "reset" + param "token" |
| 11 | saml_assertion_replay | vuln "SAML" |
| 12 | magic_link_token_reuse | vuln "magic link" or param "magic" |
| 13 | oauth_pkce_downgrade | vuln "OAuth" + param "code_challenge" |
| 14 | remember_me_token_weakness | obs with "remember" cookie |
| 15 | concurrent_session_confusion | obs with login endpoint |
| 16 | account_recovery_bruteforce | param "security_question"/"answer" |
| 17 | device_binding_bypass | vuln "2FA" + obs with device fingerprint |
| 18 | registration_toctou | obs with registration endpoint |
| 19 | auth_token_websocket_theft | obs WebSocket + param token |
| 20 | open_redirect_token_theft | vuln "open redirect" + vuln "OAuth" |
| 21 | csrf_email_change_ato | vuln "CSRF" + param "email" |
| 22 | subdomain_takeover_cookie_stealing | vuln "subdomain takeover" |

Commit: `git commit -m "feat(chain-worker): add 22 auth/session chain templates"`

#### Task 13: Injection/Execution (22 chains) — `chains/injection_execution.py`

Chains 23-44. Each evaluates for its injection type (LFI, SQLi, SSTI, etc.).

Commit: `git commit -m "feat(chain-worker): add 22 injection/execution chain templates"`

#### Task 14: SSRF/Infrastructure (20 chains) — `chains/ssrf_infrastructure.py`

Chains 45-64. Each evaluates for SSRF-type vulns + target infrastructure.

Commit: `git commit -m "feat(chain-worker): add 20 SSRF/infrastructure chain templates"`

#### Task 15: XSS/Client-Side (19 chains) — `chains/xss_client_side.py`

Chains 65-83. Each evaluates for XSS-type vulns + client-side targets.

Commit: `git commit -m "feat(chain-worker): add 19 XSS/client-side chain templates"`

#### Task 16: File Processing (19 chains) — `chains/file_processing.py`

Chains 84-102. Each evaluates for file upload vulns + processing targets.

Commit: `git commit -m "feat(chain-worker): add 19 file processing chain templates"`

#### Task 17: Header/Protocol (20 chains) — `chains/header_protocol.py`

Chains 103-122. Each evaluates for header injection or protocol manipulation vulns.

Commit: `git commit -m "feat(chain-worker): add 20 header/protocol chain templates"`

#### Task 18: Access Control (21 chains) — `chains/access_control.py`

Chains 123-143. Each evaluates for access control or business logic flaws.

Commit: `git commit -m "feat(chain-worker): add 21 access control chain templates"`

#### Task 19: Bypass (19 chains) — `chains/bypass.py`

Chains 144-162. Each evaluates for WAF/filter presence + underlying vulnerability.

Commit: `git commit -m "feat(chain-worker): add 19 bypass chain templates"`

#### Task 20: Platform/Protocol (18 chains) — `chains/platform_protocol.py`

Chains 163-180. Each evaluates for platform-specific vulns (JWT, gRPC, WebSocket, etc.).

Commit: `git commit -m "feat(chain-worker): add 18 platform/protocol chain templates"`

---

### Task 21: Wire Up Chains Package

**Files:**
- Modify: `workers/chain_worker/chains/__init__.py`
- Test: `tests/test_chain_worker_all_chains.py`

**Step 1: Update init to import all category modules**

```python
# workers/chain_worker/chains/__init__.py
from workers.chain_worker.chains import (  # noqa: F401
    auth_session,
    injection_execution,
    ssrf_infrastructure,
    xss_client_side,
    file_processing,
    header_protocol,
    access_control,
    bypass,
    platform_protocol,
)
```

**Step 2: Write integration test**

```python
# tests/test_chain_worker_all_chains.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.registry import get_registry, get_chains_by_category
import workers.chain_worker.chains  # noqa: F401


def test_total_chain_count():
    registry = get_registry()
    assert len(registry) == 180, f"Expected 180, got {len(registry)}"


def test_category_counts():
    expected = {
        "auth_session": 22,
        "injection_execution": 22,
        "ssrf_infrastructure": 20,
        "xss_client_side": 19,
        "file_processing": 19,
        "header_protocol": 20,
        "access_control": 21,
        "bypass": 19,
        "platform_protocol": 18,
    }
    for category, count in expected.items():
        chains = get_chains_by_category(category)
        assert len(chains) == count, f"'{category}': expected {count}, got {len(chains)}"


def test_all_unique_names():
    registry = get_registry()
    names = list(registry.keys())
    assert len(names) == len(set(names))


def test_all_have_required_attributes():
    registry = get_registry()
    for name, chain in registry.items():
        assert chain.name, f"{name} missing name"
        assert chain.category, f"{name} missing category"
        assert chain.severity_on_success in ("critical", "high"), f"{name} bad severity"
```

**Step 3: Run and verify**

Run: `pytest tests/test_chain_worker_all_chains.py -v`
Expected: All 4 tests PASS

**Step 4: Commit**

```bash
git add workers/chain_worker/chains/__init__.py tests/test_chain_worker_all_chains.py
git commit -m "feat(chain-worker): wire up all 180 chain templates"
```

---

### Task 22: Orchestrator Integration

**Files:**
- Modify: `orchestrator/event_engine.py`

**Step 1: Add chain_queue trigger**

Add a function that pushes to chain_queue when any worker phase completes:

```python
from uuid import uuid4

async def _trigger_chain_worker(target_id: int, completed_phase: str) -> None:
    await push_task("chain_queue", {
        "target_id": target_id,
        "trigger_phase": completed_phase,
        "run_id": uuid4().hex,
    })
```

Call this function from the existing phase-completion handler after any phase 4-11 worker sets status to COMPLETED.

**Step 2: Commit**

```bash
git add orchestrator/event_engine.py
git commit -m "feat(orchestrator): trigger chain_queue after phase completion"
```

---

### Task 23: Final Integration Test

**Files:**
- Create: `tests/test_chain_worker_integration.py`

**Step 1: Write integration test**

```python
# tests/test_chain_worker_integration.py
import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest
from workers.chain_worker.models import TargetFindings
from workers.chain_worker.tools.findings_collector import FindingsCollector
from workers.chain_worker.tools.chain_evaluator import ChainEvaluator
from workers.chain_worker.tools.chain_executor import ChainExecutor
from workers.chain_worker.tools.chain_reporter import ChainReporter
from workers.chain_worker.pipeline import STAGES


def test_pipeline_stage_order():
    assert STAGES[0].name == "data_collection"
    assert STAGES[1].name == "chain_evaluation"
    assert STAGES[2].name == "chain_execution"
    assert STAGES[3].name == "reporting"


def test_all_tools_importable():
    assert FindingsCollector().name == "findings_collector"
    assert ChainEvaluator().name == "chain_evaluator"
    assert ChainExecutor().name == "chain_executor"
    assert ChainReporter().name == "chain_reporter"


@pytest.mark.anyio
async def test_evaluator_empty_findings():
    import workers.chain_worker.chains  # noqa: F401
    from workers.chain_worker.registry import get_registry

    findings = TargetFindings(
        target_id=999, vulnerabilities=[], assets=[], parameters=[],
        observations=[], locations=[], test_accounts=None,
    )
    evaluator = ChainEvaluator()
    buckets = await evaluator.evaluate_all(findings)
    assert len(buckets["viable"]) == 0
    total = len(buckets["not_viable"]) + len(buckets["partial"]) + len(buckets["awaiting_accounts"])
    assert total == len(get_registry())
```

**Step 2: Run all chain worker tests**

Run: `pytest tests/test_chain_worker*.py -v`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add tests/test_chain_worker_integration.py
git commit -m "test(chain-worker): add integration tests"
```

---

## Execution Summary

| Task | Component | Files | Chains |
|------|-----------|-------|--------|
| 1 | Core models | models.py | -- |
| 2 | Registry | registry.py | -- |
| 3 | Concurrency | concurrency.py | -- |
| 4 | Base tool | base_tool.py | -- |
| 5 | FindingsCollector | tools/findings_collector.py | -- |
| 6 | ChainEvaluator | tools/chain_evaluator.py | -- |
| 7 | ChainExecutor | tools/chain_executor.py | -- |
| 8 | ChainReporter | tools/chain_reporter.py | -- |
| 9 | Pipeline | pipeline.py | -- |
| 10 | Main entry | main.py | -- |
| 11 | Docker | Dockerfile.chain, compose | -- |
| 12 | Auth/session | chains/auth_session.py | 22 |
| 13 | Injection | chains/injection_execution.py | 22 |
| 14 | SSRF | chains/ssrf_infrastructure.py | 20 |
| 15 | XSS | chains/xss_client_side.py | 19 |
| 16 | File processing | chains/file_processing.py | 19 |
| 17 | Header/protocol | chains/header_protocol.py | 20 |
| 18 | Access control | chains/access_control.py | 21 |
| 19 | Bypass | chains/bypass.py | 19 |
| 20 | Platform | chains/platform_protocol.py | 18 |
| 21 | Wire up | chains/__init__.py | 180 total |
| 22 | Orchestrator | event_engine.py | -- |
| 23 | Integration | test_integration.py | -- |
