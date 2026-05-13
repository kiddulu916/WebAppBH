# Info Gathering Stage 2 — Web Server Fingerprint Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rebuild Stage 2 (`web_server_fingerprint`, WSTG-INFO-02) to fingerprint a single host with 8 probe units, an in-memory aggregator that emits one summary Observation plus info-leak Vulnerabilities, configurable intensity (low/medium/high), and proper Asset-scoped linkage of every row.

**Architecture:** Pipeline preamble resolves the subject Asset's ID once, then passes `(target_id, asset_id, host, intensity)` into every probe via kwargs. Probes are mostly in-process `aiohttp` calls; only `tlsx`, `wafw00f`, and `whatweb` shell out. After `asyncio.gather` collects `ProbeResult` objects, a `FingerprintAggregator` writes one `summary` Observation and any `INFO`/`LOW` Vulnerability rows. All rows hang off the subject Asset (`asset_id` + `target_id`).

**Tech Stack:** Python 3.11+, `aiohttp`, async SQLAlchemy 2.x (aiosqlite for tests, asyncpg in prod), Redis Streams, pytest + pytest-anyio + `aioresponses`, Next.js 16.1 / React 19.2 / Playwright e2e, `tlsx` and `wafw00f` CLIs.

**Design doc:** `docs/plans/design/2026-05-11-info-gathering-stage2-fingerprint-design.md`

---

## Conventions

- Every task is TDD: write the failing test, run to confirm failure, implement, run to confirm pass, commit.
- Async tests use `@pytest.mark.anyio` and the `anyio_backend = "asyncio"` fixture from `tests/conftest.py`.
- Subprocess calls go through `InfoGatheringTool.run_subprocess` (never `shell=True`).
- DB writes go through helpers on `InfoGatheringTool` — no ad-hoc `session.add` in probes.
- Commit message convention: `feat(stage2): ...`, `fix(stage2): ...`, `test(stage2): ...`.

---

## Phase 0 — Preconditions: fix base_tool helpers

### Task 0.1: Add test for `save_observation` signature fix

**Files:**
- Test: `tests/test_info_gathering_base_tool.py` (create)

**Step 1: Write the failing test**

```python
# tests/test_info_gathering_base_tool.py
"""Regression tests for InfoGatheringTool base helpers."""
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.base_tool import InfoGatheringTool


class _Dummy(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs):
        return {"found": 0}


class TestSaveObservation:
    @pytest.mark.anyio
    async def test_save_observation_takes_asset_id_not_target_id(self):
        """save_observation must accept asset_id as first positional arg."""
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            sess.refresh = AsyncMock(side_effect=lambda obs: setattr(obs, "id", 42))
            obs_id = await tool.save_observation(
                asset_id=501,
                tech_stack={"_probe": "banner", "server": "nginx"},
                status_code=200,
                headers={"Server": "nginx"},
            )
        assert obs_id == 42
```

**Step 2: Run test to verify it fails (or passes — confirm baseline)**

Run: `pytest tests/test_info_gathering_base_tool.py::TestSaveObservation -v`
Expected: PASS (the signature is already correct in `base_tool.py:115`; this test locks the contract before we fix the broken callers).

**Step 3: Commit**

```bash
git add tests/test_info_gathering_base_tool.py
git commit -m "test(stage2): lock save_observation signature contract"
```

---

### Task 0.2: Fix `Httpx` `save_observation` call site

**Files:**
- Modify: `workers/info_gathering/tools/httpx.py:52-61`
- Test: `tests/test_info_gathering_base_tool.py` (extend)

**Step 1: Add failing regression test**

```python
# tests/test_info_gathering_base_tool.py — append
import json
from workers.info_gathering.tools.httpx import Httpx


class TestHttpxObservationLinkage:
    @pytest.mark.anyio
    async def test_httpx_writes_observation_against_asset_id(self):
        """Httpx must call save_observation with asset_id, not target_id."""
        tool = Httpx()
        line = json.dumps({"url": "https://a.com", "status_code": 200, "title": "T", "tech": ["nginx"]})
        with patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=line):
            with patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=1) as save:
                with patch("workers.info_gathering.tools.httpx.get_session") as mock_sess:
                    sess = AsyncMock()
                    sess.execute = AsyncMock()
                    sess.execute.return_value.all = lambda: [("a.com",)]
                    mock_sess.return_value.__aenter__.return_value = sess
                    mock_sess.return_value.__aexit__.return_value = False
                    await tool.execute(target_id=1, asset_id=501, host="a.com")
        kwargs = save.call_args.kwargs
        assert "asset_id" in kwargs
        assert kwargs["asset_id"] == 501
        assert "target_id" not in kwargs
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_info_gathering_base_tool.py::TestHttpxObservationLinkage -v`
Expected: FAIL — current `httpx.py:52` passes `target_id` and a stray positional `"http_probe"`.

**Step 3: Rewrite `httpx.py` to call `save_observation(asset_id=..., tech_stack=..., status_code=..., headers=...)`**

```python
# workers/info_gathering/tools/httpx.py
"""Httpx wrapper — single-host HTTP liveness probe."""
import json
import tempfile
import os

from workers.info_gathering.base_tool import InfoGatheringTool


class Httpx(InfoGatheringTool):
    """HTTP liveness probe using the httpx binary against a single host."""

    async def execute(self, target_id: int, **kwargs):
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return {"found": 0}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(host)
            input_file = f.name

        try:
            cmd = [
                "httpx", "-l", input_file,
                "-json", "-silent", "-status-code", "-title",
                "-tech-detect", "-follow-redirects",
            ]
            stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
            count = 0
            for line in stdout.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                await self.save_observation(
                    asset_id=asset_id,
                    tech_stack={
                        "_probe": "liveness",
                        "url": data.get("url", ""),
                        "tech": data.get("tech", []),
                    },
                    page_title=data.get("title"),
                    status_code=data.get("status_code"),
                )
                count += 1
            return {"found": count}
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_info_gathering_base_tool.py::TestHttpxObservationLinkage -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/test_info_gathering_base_tool.py workers/info_gathering/tools/httpx.py
git commit -m "fix(stage2): httpx must write observations against asset_id"
```

---

### Task 0.3: Fix `WhatWeb` `save_observation` call site

**Files:**
- Modify: `workers/info_gathering/tools/whatweb.py`
- Test: `tests/test_info_gathering_base_tool.py` (extend)

**Step 1: Write failing test**

```python
# tests/test_info_gathering_base_tool.py — append
from workers.info_gathering.tools.whatweb import WhatWeb


class TestWhatWebObservationLinkage:
    @pytest.mark.anyio
    async def test_whatweb_writes_observation_against_asset_id(self):
        tool = WhatWeb()
        ww_json = json.dumps([{"target": "https://a.com", "plugins": {"Apache": {}}}])
        with patch.object(tool, "run_subprocess", new_callable=AsyncMock, return_value=ww_json):
            with patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=1) as save:
                await tool.execute(target_id=1, asset_id=501, host="a.com", intensity="low")
        kwargs = save.call_args.kwargs
        assert kwargs["asset_id"] == 501
```

**Step 2: Run** → FAIL.

**Step 3: Rewrite `whatweb.py`**

```python
# workers/info_gathering/tools/whatweb.py
"""WhatWeb wrapper — application-layer fingerprint for a single host."""
import json

from workers.info_gathering.base_tool import InfoGatheringTool


class WhatWeb(InfoGatheringTool):
    """Application-layer fingerprint using WhatWeb."""

    async def execute(self, target_id: int, **kwargs):
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        intensity = kwargs.get("intensity", "low")
        if not host or not asset_id:
            return {"found": 0}

        cmd = ["whatweb", "--json", "-"]
        if intensity == "high":
            cmd += ["-a", "3"]
        cmd.append(f"https://{host}")

        try:
            stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
        except Exception:
            return {"found": 0}

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {"found": 0}
        if not isinstance(data, list):
            return {"found": 0}

        count = 0
        for entry in data:
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={
                    "_probe": "app_fingerprint",
                    "host": entry.get("target", ""),
                    "plugins": entry.get("plugins", {}),
                },
            )
            count += 1
        return {"found": count}
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add tests/test_info_gathering_base_tool.py workers/info_gathering/tools/whatweb.py
git commit -m "fix(stage2): whatweb writes observations against asset_id and honors intensity"
```

---

### Task 0.4: Add `save_location` helper to `InfoGatheringTool`

**Files:**
- Modify: `workers/info_gathering/base_tool.py`
- Test: `tests/test_info_gathering_base_tool.py` (extend)

**Step 1: Write failing test**

```python
# tests/test_info_gathering_base_tool.py — append
class TestSaveLocation:
    @pytest.mark.anyio
    async def test_save_location_creates_row(self):
        tool = _Dummy()
        with patch("workers.info_gathering.base_tool.get_session") as mock_sess:
            sess = AsyncMock()
            mock_sess.return_value.__aenter__.return_value = sess
            mock_sess.return_value.__aexit__.return_value = False
            sess.refresh = AsyncMock(side_effect=lambda loc: setattr(loc, "id", 9))
            loc_id = await tool.save_location(
                asset_id=501, port=443, protocol="tcp", service="https", state="open",
            )
        assert loc_id == 9
```

**Step 2: Run** → FAIL (`save_location` does not exist).

**Step 3: Implement in `workers/info_gathering/base_tool.py` after `save_observation`**

```python
async def save_location(
    self, asset_id: int, port: int, protocol: str | None = None,
    service: str | None = None, state: str | None = None,
) -> int | None:
    """Upsert a Location row (asset_id, port, protocol) → row ID."""
    from lib_webbh.database import Location
    from sqlalchemy import select
    async with get_session() as session:
        stmt = select(Location).where(
            Location.asset_id == asset_id,
            Location.port == port,
            Location.protocol == protocol,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing is not None:
            if service:
                existing.service = service
            if state:
                existing.state = state
            await session.commit()
            return existing.id
        loc = Location(
            asset_id=asset_id, port=port, protocol=protocol,
            service=service, state=state,
        )
        session.add(loc)
        await session.commit()
        await session.refresh(loc)
        return loc.id
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/base_tool.py tests/test_info_gathering_base_tool.py
git commit -m "feat(stage2): add save_location helper to InfoGatheringTool"
```

---

### Task 0.5: Add `resolve_or_create_asset` helper

**Files:**
- Modify: `workers/info_gathering/base_tool.py`
- Test: `tests/test_info_gathering_base_tool.py` (extend)

**Step 1: Write failing tests covering three host types**

```python
# tests/test_info_gathering_base_tool.py — append
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from lib_webbh.database import Base, Target, Asset


@pytest.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as sess:
        yield sess
    await engine.dispose()


class TestResolveOrCreateAsset:
    @pytest.mark.anyio
    async def test_resolves_existing_subdomain_asset(self, db_session, monkeypatch):
        # seed Target + Asset
        t = Target(company_name="X", base_domain="acme.com")
        db_session.add(t); await db_session.commit(); await db_session.refresh(t)
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="api.acme.com")
        db_session.add(a); await db_session.commit(); await db_session.refresh(a)

        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def fake_session():
            yield db_session
        monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_session)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(t.id, "api.acme.com", base_domain="acme.com")
        assert asset_id == a.id

    @pytest.mark.anyio
    async def test_creates_subdomain_for_unseen_host(self, db_session, monkeypatch):
        t = Target(company_name="X", base_domain="acme.com")
        db_session.add(t); await db_session.commit(); await db_session.refresh(t)
        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def fake_session():
            yield db_session
        monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_session)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(t.id, "new.acme.com", base_domain="acme.com")
        assert asset_id is not None
        row = (await db_session.execute(
            __import__("sqlalchemy").select(Asset).where(Asset.id == asset_id)
        )).scalar_one()
        assert row.asset_type == "subdomain"
        assert row.asset_value == "new.acme.com"

    @pytest.mark.anyio
    async def test_creates_ip_type_for_ip_host(self, db_session, monkeypatch):
        t = Target(company_name="X", base_domain="acme.com")
        db_session.add(t); await db_session.commit(); await db_session.refresh(t)
        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def fake_session():
            yield db_session
        monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_session)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(t.id, "203.0.113.10", base_domain="acme.com")
        row = (await db_session.execute(
            __import__("sqlalchemy").select(Asset).where(Asset.id == asset_id)
        )).scalar_one()
        assert row.asset_type == "ip"

    @pytest.mark.anyio
    async def test_resolves_existing_base_domain_asset(self, db_session, monkeypatch):
        t = Target(company_name="X", base_domain="acme.com")
        db_session.add(t); await db_session.commit(); await db_session.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="acme.com")
        db_session.add(a); await db_session.commit(); await db_session.refresh(a)

        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def fake_session():
            yield db_session
        monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_session)

        tool = _Dummy()
        asset_id = await tool.resolve_or_create_asset(t.id, "acme.com", base_domain="acme.com")
        assert asset_id == a.id
```

**Step 2: Run** → all four FAIL.

**Step 3: Implement in `base_tool.py`**

```python
async def resolve_or_create_asset(
    self, target_id: int, host: str, base_domain: str,
) -> int:
    """Return the Asset.id for `host` under `target_id`, creating one if missing."""
    import ipaddress
    from lib_webbh.database import Asset
    from sqlalchemy import select

    try:
        ipaddress.ip_address(host)
        asset_type = "ip"
    except ValueError:
        asset_type = "domain" if host == base_domain else "subdomain"

    async with get_session() as session:
        stmt = select(Asset).where(
            Asset.target_id == target_id,
            Asset.asset_type == asset_type,
            Asset.asset_value == host,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing.id
        asset = Asset(
            target_id=target_id, asset_type=asset_type,
            asset_value=host, source_tool="pipeline_preamble",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        return asset.id
```

**Step 4: Run** → all four PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/base_tool.py tests/test_info_gathering_base_tool.py
git commit -m "feat(stage2): add resolve_or_create_asset helper for pipeline preamble"
```

---

## Phase 1 — ProbeResult dataclass and FingerprintAggregator

### Task 1.1: Create `ProbeResult` and `FingerprintAggregator` skeleton

**Files:**
- Create: `workers/info_gathering/fingerprint_aggregator.py`
- Test: `tests/test_fingerprint_aggregator.py` (create)

**Step 1: Write failing tests**

```python
# tests/test_fingerprint_aggregator.py
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.fingerprint_aggregator import (
    FingerprintAggregator, ProbeResult, WEIGHTS,
)


class TestWeights:
    def test_weights_table_contains_required_keys(self):
        for key in ("banner.server", "banner.x_powered_by", "tls.cert_issuer",
                    "header_order", "method_options", "error_page_signature",
                    "waf_active", "waf_passive", "app_fingerprint"):
            assert key in WEIGHTS


class TestProbeResult:
    def test_probe_result_default_no_error(self):
        r = ProbeResult(probe="banner", obs_id=1, signals={"server": "nginx"})
        assert r.error is None
```

**Step 2: Run** → FAIL (`ImportError`).

**Step 3: Implement minimal skeleton**

```python
# workers/info_gathering/fingerprint_aggregator.py
"""FingerprintAggregator: consolidates Stage 2 probe results into one summary Observation."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

WEIGHTS: dict[str, float] = {
    "banner.server":        0.6,
    "banner.x_powered_by":  0.6,
    "tls.cert_issuer":      0.5,
    "header_order":         0.3,
    "method_options":       0.2,
    "error_page_signature": 0.7,
    "waf_active":           0.9,
    "waf_passive":          0.4,
    "app_fingerprint":      0.5,
}

CONFIDENCE_THRESHOLD = 0.5

SLOTS = ("edge", "origin_server", "framework", "os", "tls", "waf")


@dataclass
class ProbeResult:
    probe: str
    obs_id: int | None
    signals: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class FingerprintAggregator:
    def __init__(self, asset_id: int, target_id: int, intensity: str = "low"):
        self.asset_id = asset_id
        self.target_id = target_id
        self.intensity = intensity
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/fingerprint_aggregator.py tests/test_fingerprint_aggregator.py
git commit -m "feat(stage2): scaffold FingerprintAggregator and WEIGHTS table"
```

---

### Task 1.2: Implement `score()` per-slot scoring

**Files:**
- Modify: `workers/info_gathering/fingerprint_aggregator.py`
- Test: `tests/test_fingerprint_aggregator.py` (extend)

**Step 1: Write failing tests**

```python
class TestScoring:
    def test_single_signal_below_threshold_is_null(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [ProbeResult(probe="banner", obs_id=1,
                               signals={"edge": [{"src": "header_order", "value": "Cloudflare", "w": 0.3}]})]
        slot = agg._score_slot("edge", results)
        assert slot["vendor"] is None
        assert slot["confidence"] == pytest.approx(0.3)

    def test_three_signals_sum_above_threshold(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={"edge": [
                {"src": "banner.server", "value": "Cloudflare", "w": 0.6},
            ]}),
            ProbeResult(probe="tls", obs_id=2, signals={"edge": [
                {"src": "tls.cert_issuer", "value": "Cloudflare Inc", "w": 0.5},
            ]}),
            ProbeResult(probe="waf", obs_id=3, signals={"edge": [
                {"src": "waf_passive", "value": "cf-ray header", "w": 0.4},
            ]}),
        ]
        slot = agg._score_slot("edge", results)
        assert slot["vendor"] == "Cloudflare"
        assert slot["confidence"] == 1.0  # clamped to 1.0

    def test_conflict_flag_when_two_vendors_tie(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={"origin_server": [
                {"src": "banner.server", "value": "nginx", "w": 0.6},
            ]}),
            ProbeResult(probe="error_page", obs_id=2, signals={"origin_server": [
                {"src": "error_page_signature", "value": "Apache", "w": 0.7},
            ]}),
        ]
        slot = agg._score_slot("origin_server", results)
        assert slot["conflict"] is True
        assert {c["vendor"] for c in slot["candidates"]} == {"nginx", "Apache"}

    def test_errored_probe_excluded(self):
        agg = FingerprintAggregator(asset_id=1, target_id=1)
        results = [
            ProbeResult(probe="banner", obs_id=None, signals={}, error="connection refused"),
        ]
        slot = agg._score_slot("origin_server", results)
        assert slot["vendor"] is None
        assert slot["confidence"] == 0.0
```

**Step 2: Run** → FAIL.

**Step 3: Implement `_score_slot`**

```python
def _score_slot(self, slot: str, results: list[ProbeResult]) -> dict:
    """Sum weights per (slot, vendor) across non-errored probes."""
    totals: dict[str, float] = {}
    signals_by_vendor: dict[str, list[dict]] = {}
    for r in results:
        if r.error is not None:
            continue
        for signal in r.signals.get(slot, []):
            vendor = signal["value"]
            w = signal["w"]
            totals[vendor] = totals.get(vendor, 0.0) + w
            signals_by_vendor.setdefault(vendor, []).append(signal)

    if not totals:
        return {"vendor": None, "confidence": 0.0, "signals": [], "conflict": False}

    sorted_vendors = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    top_vendor, top_score = sorted_vendors[0]
    top_score_clamped = min(top_score, 1.0)

    above_threshold = [v for v, s in sorted_vendors if s >= CONFIDENCE_THRESHOLD]
    conflict = len(above_threshold) > 1

    if top_score < CONFIDENCE_THRESHOLD:
        return {
            "vendor": None,
            "confidence": top_score_clamped,
            "signals": [s for sigs in signals_by_vendor.values() for s in sigs],
            "conflict": False,
        }

    if conflict:
        return {
            "vendor": top_vendor,
            "confidence": top_score_clamped,
            "conflict": True,
            "candidates": [
                {"vendor": v, "confidence": min(s, 1.0), "signals": signals_by_vendor[v]}
                for v, s in sorted_vendors if s >= CONFIDENCE_THRESHOLD
            ],
        }

    return {
        "vendor": top_vendor,
        "confidence": top_score_clamped,
        "signals": signals_by_vendor[top_vendor],
        "conflict": False,
    }
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/fingerprint_aggregator.py tests/test_fingerprint_aggregator.py
git commit -m "feat(stage2): per-slot weighted scoring with conflict detection"
```

---

### Task 1.3: Implement `write_summary()` end-to-end

**Files:**
- Modify: `workers/info_gathering/fingerprint_aggregator.py`
- Test: `tests/test_fingerprint_aggregator.py` (extend)

**Step 1: Write failing test**

```python
class TestWriteSummary:
    @pytest.mark.anyio
    async def test_write_summary_records_partial_when_probe_errored(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42, intensity="low")
        results = [
            ProbeResult(probe="banner", obs_id=1, signals={"origin_server": [
                {"src": "banner.server", "value": "nginx", "w": 0.6},
            ]}),
            ProbeResult(probe="tls", obs_id=None, signals={}, error="handshake failed"),
        ]
        with patch.object(agg, "_save_summary_observation", new_callable=AsyncMock,
                          return_value=99) as save:
            obs_id = await agg.write_summary(results)
        assert obs_id == 99
        payload = save.call_args.args[0]
        assert payload["_probe"] == "summary"
        assert payload["intensity"] == "low"
        assert payload["partial"] is True
        assert payload["fingerprint"]["origin_server"]["vendor"] == "nginx"
        assert payload["raw_probe_obs_ids"] == [1]
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
async def write_summary(self, results: list[ProbeResult]) -> int | None:
    partial = any(r.error is not None for r in results)
    fingerprint = {slot: self._score_slot(slot, results) for slot in SLOTS}
    fingerprint["tls"] = self._merge_tls(results)
    payload = {
        "_probe": "summary",
        "intensity": self.intensity,
        "partial": partial,
        "fingerprint": fingerprint,
        "raw_probe_obs_ids": [r.obs_id for r in results if r.obs_id is not None],
    }
    return await self._save_summary_observation(payload)

def _merge_tls(self, results: list[ProbeResult]) -> dict:
    for r in results:
        if r.probe == "tls" and r.error is None:
            return r.signals.get("tls_summary", {})
    return {}

async def _save_summary_observation(self, payload: dict) -> int | None:
    from lib_webbh import get_session
    from lib_webbh.database import Observation
    async with get_session() as session:
        obs = Observation(asset_id=self.asset_id, tech_stack=payload)
        session.add(obs)
        await session.commit()
        await session.refresh(obs)
        return obs.id
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/fingerprint_aggregator.py tests/test_fingerprint_aggregator.py
git commit -m "feat(stage2): aggregator writes summary observation"
```

---

### Task 1.4: Add info-leak Vulnerability emission

**Files:**
- Modify: `workers/info_gathering/fingerprint_aggregator.py`
- Create: `workers/info_gathering/fingerprint_signatures.py`
- Test: `tests/test_fingerprint_aggregator.py` (extend)

**Step 1: Write failing tests**

```python
class TestInfoLeakEmission:
    @pytest.mark.anyio
    async def test_emits_vuln_for_x_powered_by(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42)
        raw = {"banner": {"x_powered_by": "Express", "obs_id": 7, "headers": {"X-Powered-By": "Express"}}}
        with patch.object(agg, "_save_vuln", new_callable=AsyncMock, return_value=11) as save:
            ids = await agg.emit_info_leaks({"origin_server": {"vendor": None}}, raw)
        assert 11 in ids
        kwargs = save.call_args.kwargs
        assert kwargs["title"] == "Framework disclosure via X-Powered-By"
        assert kwargs["severity"] == "INFO"
        assert kwargs["section_id"] == "4.1.2"
        assert kwargs["evidence"]["probe_obs_id"] == 7

    @pytest.mark.anyio
    async def test_no_vulns_when_no_info_leak(self):
        agg = FingerprintAggregator(asset_id=501, target_id=42)
        raw = {"banner": {"headers": {}}}
        with patch.object(agg, "_save_vuln", new_callable=AsyncMock) as save:
            ids = await agg.emit_info_leaks({"origin_server": {"vendor": None}}, raw)
        assert ids == []
        assert save.call_count == 0
```

**Step 2: Run** → FAIL.

**Step 3: Implement signatures module + emission**

```python
# workers/info_gathering/fingerprint_signatures.py
"""Static signature tables for Stage 2."""

DEFAULT_ERROR_LEAKERS = frozenset({
    "apache-default-404", "nginx-default-404", "iis-default-404",
    "tomcat-default-404", "express-default-404", "django-default-debug",
})

INTERNAL_DEBUG_HEADERS = frozenset({
    "x-debug", "x-debug-token", "x-debug-token-link",
    "x-request-id-internal", "x-backend-server", "x-served-by-internal",
})

WAF_PASSIVE_PATTERNS = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "cookies": ["__cf_bm", "cf_clearance"]},
    "Akamai":     {"headers": ["akamai-grn", "x-akamai-transformed"], "cookies": ["ak_bmsc"]},
    "AWS WAF":    {"headers": ["x-amzn-waf-action"], "cookies": []},
    "F5 BIG-IP":  {"headers": [], "cookies": ["BIGipServer"]},
    "Sucuri":     {"headers": ["x-sucuri-id", "x-sucuri-cache"], "cookies": []},
}

CDN_CERT_ISSUERS = {
    "Cloudflare Inc": "Cloudflare",
    "Amazon": "CloudFront",
    "Akamai": "Akamai",
    "Fastly": "Fastly",
    "Microsoft Azure": "AzureFD",
}
```

```python
# workers/info_gathering/fingerprint_aggregator.py — append
from workers.info_gathering.fingerprint_signatures import (
    DEFAULT_ERROR_LEAKERS, INTERNAL_DEBUG_HEADERS,
)


async def emit_info_leaks(self, fingerprint: dict, raw: dict) -> list[int]:
    vuln_ids: list[int] = []

    origin = fingerprint.get("origin_server", {})
    if origin.get("vendor") and origin.get("version"):
        vuln_ids.append(await self._save_vuln(
            title="Server software and version disclosure",
            severity="INFO",
            evidence={
                "vendor": origin["vendor"], "version": origin["version"],
                "probe_obs_id": raw.get("banner", {}).get("obs_id"),
            },
        ))

    banner = raw.get("banner", {})
    if "x_powered_by" in banner and banner["x_powered_by"]:
        vuln_ids.append(await self._save_vuln(
            title="Framework disclosure via X-Powered-By",
            severity="INFO",
            evidence={
                "header": "X-Powered-By",
                "value": banner["x_powered_by"],
                "probe_obs_id": banner.get("obs_id"),
            },
        ))

    err = raw.get("error_page_404", {})
    if err.get("signature_match") in DEFAULT_ERROR_LEAKERS:
        vuln_ids.append(await self._save_vuln(
            title="Default error page exposes server internals",
            severity="LOW",
            evidence={
                "signature": err["signature_match"],
                "probe_obs_id": err.get("obs_id"),
            },
        ))

    debug_hits = [h for h in banner.get("headers", {}) if h.lower() in INTERNAL_DEBUG_HEADERS]
    if debug_hits:
        vuln_ids.append(await self._save_vuln(
            title="Internal debug header exposed to public",
            severity="LOW",
            evidence={"headers": debug_hits, "probe_obs_id": banner.get("obs_id")},
        ))

    return vuln_ids


async def _save_vuln(self, *, title: str, severity: str, evidence: dict) -> int:
    from lib_webbh import get_session
    from lib_webbh.database import Vulnerability
    async with get_session() as session:
        vuln = Vulnerability(
            target_id=self.target_id,
            asset_id=self.asset_id,
            severity=severity,
            title=title,
            worker_type="info_gathering",
            section_id="4.1.2",
            stage_name="web_server_fingerprint",
            source_tool="fingerprint_aggregator",
            vuln_type="information_disclosure",
            evidence=evidence,
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)
        return vuln.id
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/fingerprint_aggregator.py workers/info_gathering/fingerprint_signatures.py tests/test_fingerprint_aggregator.py
git commit -m "feat(stage2): aggregator emits info-leak vulnerabilities"
```

---

## Phase 2 — Probe units

Each probe in this phase follows the same pattern: define a small `aiohttp`-based probe class subclassing `InfoGatheringTool`, return a `ProbeResult`, write one Observation. Tests mock HTTP via `aioresponses` for in-process probes and `run_subprocess` for shell-outs.

### Task 2.1: `LivenessProbe`

**Files:**
- Create: `workers/info_gathering/tools/liveness_probe.py`
- Test: `tests/test_stage2_liveness_probe.py`

**Step 1: Write failing tests**

```python
# tests/test_stage2_liveness_probe.py
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.liveness_probe import LivenessProbe, HTTP_PORTS


class TestLivenessProbe:
    def test_http_ports_set(self):
        assert HTTP_PORTS == [80, 443, 8000, 8008, 8080, 8443, 4443, 8888]

    @pytest.mark.anyio
    async def test_writes_one_location_per_alive_port(self):
        probe = LivenessProbe()
        httpx_out = '\n'.join([
            '{"url":"https://api.acme.com:443","port":"443","status_code":200,"tech":["nginx"]}',
            '{"url":"http://api.acme.com:80","port":"80","status_code":301,"tech":[]}',
        ])
        with patch.object(probe, "run_subprocess", new_callable=AsyncMock, return_value=httpx_out):
            with patch.object(probe, "save_location", new_callable=AsyncMock, return_value=1) as loc:
                with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=10) as obs:
                    result = await probe.execute(
                        target_id=1, asset_id=501, host="api.acme.com", intensity="low",
                    )
        assert loc.call_count == 2
        assert obs.call_count == 1
        assert result.probe == "liveness"
        assert result.obs_id == 10
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
# workers/info_gathering/tools/liveness_probe.py
"""LivenessProbe — single-host HTTP port liveness via httpx binary."""
import json
import tempfile
import os

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

HTTP_PORTS = [80, 443, 8000, 8008, 8080, 8443, 4443, 8888]


class LivenessProbe(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs["host"]
        asset_id = kwargs["asset_id"]

        targets = "\n".join(f"{host}:{p}" for p in HTTP_PORTS)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(targets); input_file = f.name

        try:
            cmd = ["httpx", "-l", input_file, "-json", "-silent",
                   "-status-code", "-tech-detect", "-no-color"]
            try:
                stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
            except Exception as e:
                return ProbeResult(probe="liveness", obs_id=None, signals={}, error=str(e))

            alive = []
            for line in stdout.strip().splitlines():
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                port = int(data.get("port") or 0)
                if not port: continue
                alive.append({"port": port, "status_code": data.get("status_code"),
                              "tech": data.get("tech", []), "url": data.get("url", "")})
                proto = "tcp"
                service = "https" if port in (443, 8443, 4443) else "http"
                await self.save_location(
                    asset_id=asset_id, port=port, protocol=proto,
                    service=service, state="open",
                )

            obs_id = await self.save_observation(
                asset_id=asset_id,
                tech_stack={"_probe": "liveness", "alive": alive, "host": host},
            )
            return ProbeResult(probe="liveness", obs_id=obs_id, signals={"alive_ports": [a["port"] for a in alive]})
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/liveness_probe.py tests/test_stage2_liveness_probe.py
git commit -m "feat(stage2): LivenessProbe writes Locations + liveness Observation"
```

---

### Task 2.2: `BannerProbe`

**Files:**
- Create: `workers/info_gathering/tools/banner_probe.py`
- Test: `tests/test_stage2_banner_probe.py`

**Step 1: Write failing tests**

```python
# tests/test_stage2_banner_probe.py
import pytest
from unittest.mock import AsyncMock, patch
from aioresponses import aioresponses
from workers.info_gathering.tools.banner_probe import BannerProbe


class TestBannerProbe:
    @pytest.mark.anyio
    async def test_extracts_server_and_x_powered_by(self):
        probe = BannerProbe()
        with aioresponses() as m:
            m.get("https://api.acme.com/", status=200, body="ok",
                  headers={"Server": "cloudflare", "X-Powered-By": "Express",
                           "Set-Cookie": "__cf_bm=abc"})
            with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=1) as obs:
                result = await probe.execute(target_id=1, asset_id=501, host="api.acme.com", intensity="low")
        assert result.probe == "banner"
        assert result.obs_id == 1
        sig_edge = result.signals.get("edge", [])
        sig_origin = result.signals.get("origin_server", [])
        sig_fw = result.signals.get("framework", [])
        all_signals = sig_edge + sig_origin + sig_fw
        assert any(s["value"] == "Cloudflare" for s in sig_edge)
        assert any(s["src"] == "banner.x_powered_by" for s in sig_fw)

    @pytest.mark.anyio
    async def test_returns_error_on_connection_failure(self):
        probe = BannerProbe()
        with aioresponses() as m:
            from aiohttp import ClientConnectorError
            m.get("https://api.acme.com/", exception=ClientConnectorError(None, OSError("refused")))
            result = await probe.execute(target_id=1, asset_id=501, host="api.acme.com", intensity="low")
        assert result.error is not None
        assert result.obs_id is None
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
# workers/info_gathering/tools/banner_probe.py
"""BannerProbe — extracts Server / X-Powered-By / cookie hints from GET /."""
import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.fingerprint_signatures import WAF_PASSIVE_PATTERNS

_ORIGIN_KEYWORDS = {
    "apache": "Apache", "nginx": "nginx", "microsoft-iis": "IIS",
    "caddy": "Caddy", "lighttpd": "lighttpd", "tomcat": "Tomcat",
}

_EDGE_KEYWORDS = {
    "cloudflare": "Cloudflare", "cloudfront": "CloudFront",
    "akamai": "Akamai", "fastly": "Fastly",
}


class BannerProbe(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs["host"]
        asset_id = kwargs["asset_id"]
        rate_limiter = kwargs.get("rate_limiter")

        url = f"https://{host}/"
        try:
            await self.acquire_rate_limit(rate_limiter)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                                       allow_redirects=False) as resp:
                    headers = dict(resp.headers)
                    status = resp.status
                    cookies = resp.headers.getall("Set-Cookie", [])
        except Exception as e:
            return ProbeResult(probe="banner", obs_id=None, signals={}, error=str(e))

        server = headers.get("Server", "")
        x_powered_by = headers.get("X-Powered-By", "")
        signals: dict[str, list[dict]] = {"edge": [], "origin_server": [], "framework": []}

        server_lower = server.lower()
        for kw, vendor in _EDGE_KEYWORDS.items():
            if kw in server_lower:
                signals["edge"].append({"src": "banner.server", "value": vendor, "w": 0.6})
                break
        else:
            for kw, vendor in _ORIGIN_KEYWORDS.items():
                if kw in server_lower:
                    signals["origin_server"].append({"src": "banner.server", "value": vendor, "w": 0.6})
                    break

        if x_powered_by:
            signals["framework"].append({"src": "banner.x_powered_by", "value": x_powered_by, "w": 0.6})

        cookie_blob = " ".join(cookies).lower()
        for vendor, patterns in WAF_PASSIVE_PATTERNS.items():
            if any(p.lower() in cookie_blob for p in patterns["cookies"]):
                signals["edge"].append({"src": "banner.server", "value": vendor, "w": 0.4})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "banner", "server_raw": server,
                        "x_powered_by": x_powered_by, "headers": headers},
            status_code=status, headers=headers,
        )
        signals["_raw"] = {"obs_id": obs_id, "server": server, "x_powered_by": x_powered_by,
                          "headers": headers}
        return ProbeResult(probe="banner", obs_id=obs_id, signals=signals)
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/banner_probe.py tests/test_stage2_banner_probe.py
git commit -m "feat(stage2): BannerProbe extracts Server/X-Powered-By/cookie signals"
```

---

### Task 2.3: `HeaderOrderProbe`

**Files:**
- Create: `workers/info_gathering/tools/header_order_probe.py`
- Test: `tests/test_stage2_header_order_probe.py`

**Step 1: Write failing test**

```python
# tests/test_stage2_header_order_probe.py
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.header_order_probe import HeaderOrderProbe


class TestHeaderOrderProbe:
    @pytest.mark.anyio
    async def test_records_header_order_and_casing(self):
        probe = HeaderOrderProbe()
        canned = (
            "HTTP/1.1 200 OK\r\n"
            "Date: Mon, 11 May 2026 00:00:00 GMT\r\n"
            "Content-Type: text/html\r\n"
            "Server: nginx/1.25.0\r\n"
            "\r\n"
        )
        with patch.object(probe, "_raw_get", new_callable=AsyncMock, return_value=canned):
            with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=2) as obs:
                result = await probe.execute(target_id=1, asset_id=501, host="api.acme.com", intensity="low")
        body = obs.call_args.kwargs["tech_stack"]
        assert body["order"][:3] == ["Date", "Content-Type", "Server"]
        assert body["casing"] == "Title-Case"
        assert result.probe == "header_order"
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
# workers/info_gathering/tools/header_order_probe.py
"""HeaderOrderProbe — raw-socket GET / to preserve header order/casing."""
import asyncio
import ssl

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult


def _detect_casing(headers: list[str]) -> str:
    if all(h.istitle() or "-" in h and all(p.istitle() for p in h.split("-")) for h in headers):
        return "Title-Case"
    if all(h.islower() for h in headers):
        return "lowercase"
    return "Mixed"


class HeaderOrderProbe(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs["host"]
        asset_id = kwargs["asset_id"]
        rate_limiter = kwargs.get("rate_limiter")
        try:
            await self.acquire_rate_limit(rate_limiter)
            raw = await self._raw_get(host, port=443, tls=True)
        except Exception as e:
            return ProbeResult(probe="header_order", obs_id=None, signals={}, error=str(e))

        headers_section = raw.split("\r\n\r\n", 1)[0]
        lines = headers_section.split("\r\n")[1:]
        order = [ln.split(":", 1)[0] for ln in lines if ":" in ln]
        casing = _detect_casing(order)

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "header_order", "order": order, "casing": casing},
        )
        signals = {"origin_server": [], "edge": []}
        if casing == "Title-Case" and any(h.lower() == "server" for h in order):
            pass
        return ProbeResult(probe="header_order", obs_id=obs_id, signals=signals)

    async def _raw_get(self, host: str, port: int = 443, tls: bool = True) -> str:
        ssl_ctx = ssl.create_default_context() if tls else None
        ssl_ctx.check_hostname = False if ssl_ctx else None
        if ssl_ctx is not None:
            ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: webbh\r\nConnection: close\r\n\r\n"
        writer.write(req.encode("ascii"))
        await writer.drain()
        data = b""
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=10.0)
        finally:
            writer.close()
            await writer.wait_closed()
        return data.decode("iso-8859-1", errors="replace")
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/header_order_probe.py tests/test_stage2_header_order_probe.py
git commit -m "feat(stage2): HeaderOrderProbe preserves raw header order and casing"
```

---

### Task 2.4: `MethodProbe` (intensity-gated)

**Files:**
- Create: `workers/info_gathering/tools/method_probe.py`
- Test: `tests/test_stage2_method_probe.py`

**Step 1: Write failing tests**

```python
# tests/test_stage2_method_probe.py
import pytest
from unittest.mock import AsyncMock, patch
from aioresponses import aioresponses
from workers.info_gathering.tools.method_probe import MethodProbe


class TestMethodProbe:
    @pytest.mark.anyio
    async def test_low_intensity_does_not_send_propfind(self):
        probe = MethodProbe()
        with aioresponses() as m:
            m.options("https://a.com/", status=200, headers={"Allow": "GET, HEAD"})
            m.head("https://a.com/", status=200, headers={"Content-Length": "5"})
            m.get("https://a.com/", status=200, body="hello")
            # If PROPFIND is sent, this will mismatch (no PROPFIND mock registered)
            with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=3):
                result = await probe.execute(target_id=1, asset_id=501, host="a.com", intensity="low")
        assert result.probe == "method_probe"
        assert result.error is None

    @pytest.mark.anyio
    async def test_high_intensity_includes_garbage_verb(self):
        probe = MethodProbe()
        with patch.object(probe, "_send_method", new_callable=AsyncMock,
                          return_value={"status": 405, "body_len": 0}) as send:
            with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=4):
                await probe.execute(target_id=1, asset_id=501, host="a.com", intensity="high")
        methods_sent = [call.args[1] for call in send.call_args_list]
        assert "ASDF" in methods_sent or any("ASDF" in m for m in methods_sent)
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
# workers/info_gathering/tools/method_probe.py
"""MethodProbe — HTTP method behavior probing, intensity-gated."""
import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

LOW_METHODS  = ["OPTIONS", "HEAD", "get"]   # lowercase get is allowed at low
MED_METHODS  = ["PROPFIND", "TRACE"]
HIGH_METHODS = ["ASDF", "DELETE", "PUT"]


class MethodProbe(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs["host"]
        asset_id = kwargs["asset_id"]
        intensity = kwargs.get("intensity", "low")
        rate_limiter = kwargs.get("rate_limiter")

        methods = list(LOW_METHODS)
        if intensity in ("medium", "high"):
            methods += MED_METHODS
        if intensity == "high":
            methods += HIGH_METHODS

        results: dict[str, dict] = {}
        try:
            async with aiohttp.ClientSession() as session:
                for method in methods:
                    await self.acquire_rate_limit(rate_limiter)
                    info = await self._send_method(session, method, f"https://{host}/")
                    results[method] = info
        except Exception as e:
            return ProbeResult(probe="method_probe", obs_id=None, signals={}, error=str(e))

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "method_options", "results": results, "intensity": intensity},
        )
        signals = {"origin_server": []}
        allow = results.get("OPTIONS", {}).get("allow", "")
        if "PROPFIND" in allow.upper():
            signals["origin_server"].append(
                {"src": "method_options", "value": "IIS", "w": 0.2})
        return ProbeResult(probe="method_probe", obs_id=obs_id, signals=signals)

    async def _send_method(self, session, method: str, url: str) -> dict:
        try:
            async with session.request(method.upper(), url,
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       allow_redirects=False) as resp:
                body = await resp.read()
                return {
                    "status": resp.status,
                    "body_len": len(body),
                    "allow": resp.headers.get("Allow", ""),
                    "server": resp.headers.get("Server", ""),
                }
        except Exception as e:
            return {"error": str(e)}
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/method_probe.py tests/test_stage2_method_probe.py
git commit -m "feat(stage2): MethodProbe with intensity-gated method list"
```

---

### Task 2.5: `ErrorPageProbe`

**Files:**
- Create: `workers/info_gathering/tools/error_page_probe.py`
- Test: `tests/test_stage2_error_page_probe.py`

**Step 1: Write failing tests**

```python
# tests/test_stage2_error_page_probe.py
import pytest
from unittest.mock import AsyncMock, patch
from aioresponses import aioresponses
from workers.info_gathering.tools.error_page_probe import ErrorPageProbe


class TestErrorPageProbe:
    @pytest.mark.anyio
    async def test_hashes_404_body_and_signature_matches(self):
        probe = ErrorPageProbe()
        nginx_404 = "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.0</center></body></html>"
        import re
        pattern = re.compile(r"https://a\.com/[a-z0-9]{16}")
        with aioresponses() as m:
            m.get(pattern, status=404, body=nginx_404)
            with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=5) as obs:
                result = await probe.execute(target_id=1, asset_id=501, host="a.com", intensity="low")
        body = obs.call_args.kwargs["tech_stack"]
        assert "body_sha256" in body
        assert body["signature_match"] == "nginx-default-404"
        assert any(s["src"] == "error_page_signature" and s["value"] == "nginx"
                   for s in result.signals.get("origin_server", []))
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
# workers/info_gathering/tools/error_page_probe.py
"""ErrorPageProbe — fingerprint default 404 / error pages."""
import hashlib
import secrets
import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult

# Substring → (signature_id, vendor) for the origin_server slot
_SIGNATURES = [
    ("<center>nginx",                     "nginx-default-404",   "nginx"),
    ("Apache",                            "apache-default-404",  "Apache"),
    ("IIS",                               "iis-default-404",     "IIS"),
    ("Tomcat",                            "tomcat-default-404",  "Tomcat"),
    ("Cannot GET /",                      "express-default-404", "Express"),
    ("DEBUG = True",                      "django-default-debug","Django"),
    ("ray id",                            "cloudflare-default-404", "Cloudflare"),
]


class ErrorPageProbe(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs["host"]
        asset_id = kwargs["asset_id"]
        intensity = kwargs.get("intensity", "low")
        rate_limiter = kwargs.get("rate_limiter")
        try:
            await self.acquire_rate_limit(rate_limiter)
            async with aiohttp.ClientSession() as session:
                random_path = secrets.token_hex(8)  # 16 chars
                url = f"https://{host}/{random_path}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                       allow_redirects=False) as resp:
                    body = await resp.text(errors="replace")
                    status = resp.status
        except Exception as e:
            return ProbeResult(probe="error_page", obs_id=None, signals={}, error=str(e))

        body_sha = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        signature_match: str | None = None
        signature_vendor: str | None = None
        for needle, sig_id, vendor in _SIGNATURES:
            if needle.lower() in body.lower():
                signature_match = sig_id; signature_vendor = vendor
                break

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={
                "_probe": "error_page_404",
                "body_sha256": body_sha,
                "body_len": len(body),
                "signature_match": signature_match,
                "intensity": intensity,
            },
            status_code=status,
        )
        signals: dict[str, list[dict]] = {"origin_server": [], "framework": []}
        if signature_vendor:
            slot = "framework" if signature_vendor in ("Express", "Django") else "origin_server"
            signals[slot].append({
                "src": "error_page_signature", "value": signature_vendor, "w": 0.7,
            })
        return ProbeResult(probe="error_page", obs_id=obs_id, signals=signals)
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/error_page_probe.py tests/test_stage2_error_page_probe.py
git commit -m "feat(stage2): ErrorPageProbe with signature matching"
```

---

### Task 2.6: `TLSProbe`

**Files:**
- Create: `workers/info_gathering/tools/tls_probe.py`
- Test: `tests/test_stage2_tls_probe.py`

**Step 1: Write failing test**

```python
# tests/test_stage2_tls_probe.py
import json
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.tls_probe import TLSProbe


class TestTLSProbe:
    @pytest.mark.anyio
    async def test_parses_tlsx_output(self):
        probe = TLSProbe()
        tlsx_out = json.dumps({
            "host": "api.acme.com", "ja3s_hash": "abcd1234",
            "tls_version": "tls13", "issuer_cn": "Cloudflare Inc",
            "subject_an": ["*.acme.com"], "alpn": ["h2", "http/1.1"],
        })
        with patch.object(probe, "run_subprocess", new_callable=AsyncMock, return_value=tlsx_out):
            with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=6):
                result = await probe.execute(target_id=1, asset_id=501, host="api.acme.com", intensity="low")
        assert result.probe == "tls"
        edge = result.signals.get("edge", [])
        assert any(s["value"] == "Cloudflare" for s in edge)
        assert result.signals["tls_summary"]["ja3s"] == "abcd1234"
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
# workers/info_gathering/tools/tls_probe.py
"""TLSProbe — TLS fingerprint via tlsx binary."""
import json

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.fingerprint_signatures import CDN_CERT_ISSUERS


class TLSProbe(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs["host"]
        asset_id = kwargs["asset_id"]
        rate_limiter = kwargs.get("rate_limiter")
        cmd = ["tlsx", "-u", f"{host}:443", "-json", "-silent",
               "-ja3s", "-tls-version", "-cipher", "-cn", "-an", "-alpn", "-issuer"]
        try:
            stdout = await self.run_subprocess(cmd, rate_limiter=rate_limiter)
        except Exception as e:
            return ProbeResult(probe="tls", obs_id=None, signals={}, error=str(e))

        try:
            data = json.loads(stdout.strip().splitlines()[0]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            data = {}

        tls_summary = {
            "ja3s": data.get("ja3s_hash"),
            "tls_version": data.get("tls_version"),
            "cert_issuer": data.get("issuer_cn"),
            "san": data.get("subject_an", []),
            "alpn": data.get("alpn", []),
        }
        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "tls", **tls_summary},
        )
        signals: dict[str, list[dict]] = {"edge": []}
        issuer = data.get("issuer_cn") or ""
        for needle, vendor in CDN_CERT_ISSUERS.items():
            if needle.lower() in issuer.lower():
                signals["edge"].append({"src": "tls.cert_issuer", "value": vendor, "w": 0.5})
                break
        signals["tls_summary"] = tls_summary
        return ProbeResult(probe="tls", obs_id=obs_id, signals=signals)
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/tls_probe.py tests/test_stage2_tls_probe.py
git commit -m "feat(stage2): TLSProbe via tlsx binary"
```

---

### Task 2.7: `WAFProbe`

**Files:**
- Create: `workers/info_gathering/tools/waf_probe.py`
- Test: `tests/test_stage2_waf_probe.py`

**Step 1: Write failing tests**

```python
# tests/test_stage2_waf_probe.py
import pytest
from unittest.mock import AsyncMock, patch
from aioresponses import aioresponses
from workers.info_gathering.tools.waf_probe import WAFProbe


class TestWAFProbe:
    @pytest.mark.anyio
    async def test_low_intensity_passive_only_no_wafw00f(self):
        probe = WAFProbe()
        with aioresponses() as m:
            m.get("https://a.com/", status=200, headers={"cf-ray": "abc123",
                                                         "Server": "cloudflare"})
            with patch.object(probe, "run_subprocess", new_callable=AsyncMock) as sub:
                with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=7):
                    result = await probe.execute(target_id=1, asset_id=501, host="a.com", intensity="low")
        assert sub.call_count == 0
        assert any(s["src"] == "waf_passive" for s in result.signals.get("waf", []))

    @pytest.mark.anyio
    async def test_medium_intensity_runs_wafw00f(self):
        probe = WAFProbe()
        with aioresponses() as m:
            m.get("https://a.com/", status=200, headers={})
            with patch.object(probe, "run_subprocess", new_callable=AsyncMock,
                              return_value='{"detected":true,"firewall":"Cloudflare"}'):
                with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=8):
                    result = await probe.execute(target_id=1, asset_id=501, host="a.com", intensity="medium")
        assert any(s["src"] == "waf_active" and s["value"] == "Cloudflare"
                   for s in result.signals.get("waf", []))
```

**Step 2: Run** → FAIL.

**Step 3: Implement**

```python
# workers/info_gathering/tools/waf_probe.py
"""WAFProbe — passive header/cookie matcher (low) + wafw00f active (medium/high)."""
import json
import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.fingerprint_signatures import WAF_PASSIVE_PATTERNS


class WAFProbe(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs["host"]
        asset_id = kwargs["asset_id"]
        intensity = kwargs.get("intensity", "low")
        rate_limiter = kwargs.get("rate_limiter")

        passive: dict | None = None
        try:
            await self.acquire_rate_limit(rate_limiter)
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{host}/",
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       allow_redirects=False) as resp:
                    passive = await self._passive_detect(resp)
        except Exception as e:
            return ProbeResult(probe="waf", obs_id=None, signals={}, error=str(e))

        active: dict | None = None
        if intensity in ("medium", "high"):
            try:
                stdout = await self.run_subprocess(
                    ["wafw00f", "-a", "-o", "-", "-f", "json", f"https://{host}/"],
                    rate_limiter=rate_limiter,
                )
                parsed = json.loads(stdout) if stdout.strip() else {}
                if parsed.get("detected"):
                    active = {"vendor": parsed.get("firewall")}
            except Exception:
                active = None

        signals = {"waf": []}
        if passive:
            for vendor in passive["vendors"]:
                signals["waf"].append({"src": "waf_passive", "value": vendor, "w": 0.4})
        if active and active["vendor"]:
            signals["waf"].append({"src": "waf_active", "value": active["vendor"], "w": 0.9})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "waf", "passive": passive, "active": active,
                        "intensity": intensity},
        )
        return ProbeResult(probe="waf", obs_id=obs_id, signals=signals)

    async def _passive_detect(self, resp) -> dict:
        vendors: list[str] = []
        evidence: list[str] = []
        header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
        cookie_blob = " ".join(resp.headers.getall("Set-Cookie", [])).lower()
        for vendor, patterns in WAF_PASSIVE_PATTERNS.items():
            if any(h.lower() in header_blob for h in patterns["headers"]):
                vendors.append(vendor); evidence.append(f"header({vendor})")
                continue
            if any(c.lower() in cookie_blob for c in patterns["cookies"]):
                vendors.append(vendor); evidence.append(f"cookie({vendor})")
        return {"vendors": vendors, "evidence": evidence}
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/waf_probe.py tests/test_stage2_waf_probe.py
git commit -m "feat(stage2): WAFProbe passive + intensity-gated wafw00f"
```

---

### Task 2.8: `WhatWebProbe` returns `ProbeResult`

**Files:**
- Modify: `workers/info_gathering/tools/whatweb.py`
- Test: `tests/test_stage2_whatweb_probe.py`

**Step 1: Write failing test**

```python
# tests/test_stage2_whatweb_probe.py
import json
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.whatweb import WhatWeb


class TestWhatWebProbeResult:
    @pytest.mark.anyio
    async def test_returns_probe_result_with_app_fingerprint_signals(self):
        probe = WhatWeb()
        ww = json.dumps([{"target": "https://a.com",
                          "plugins": {"Apache": {"version": ["2.4.49"]}, "PHP": {}}}])
        with patch.object(probe, "run_subprocess", new_callable=AsyncMock, return_value=ww):
            with patch.object(probe, "save_observation", new_callable=AsyncMock, return_value=9):
                result = await probe.execute(target_id=1, asset_id=501, host="a.com", intensity="low")
        assert result.probe == "app_fingerprint"
        origin = result.signals.get("origin_server", [])
        assert any(s["src"] == "app_fingerprint" and s["value"] == "Apache" for s in origin)
```

**Step 2: Run** → FAIL.

**Step 3: Update `whatweb.py` to return `ProbeResult` and emit signals**

```python
# workers/info_gathering/tools/whatweb.py — adjust execute() to return ProbeResult
from workers.info_gathering.fingerprint_aggregator import ProbeResult

_PLUGIN_SLOTS = {
    "Apache": "origin_server", "nginx": "origin_server", "IIS": "origin_server",
    "Tomcat": "origin_server", "Cloudflare": "edge", "Akamai": "edge",
    "PHP": "framework", "ASP.NET": "framework", "Django": "framework",
    "Ruby-on-Rails": "framework", "Express": "framework",
}


class WhatWeb(InfoGatheringTool):
    async def execute(self, target_id: int, **kwargs) -> ProbeResult:
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        intensity = kwargs.get("intensity", "low")
        if not host or not asset_id:
            return ProbeResult(probe="app_fingerprint", obs_id=None, signals={},
                               error="missing host/asset_id")
        cmd = ["whatweb", "--json", "-"]
        if intensity == "high":
            cmd += ["-a", "3"]
        cmd.append(f"https://{host}")
        try:
            stdout = await self.run_subprocess(cmd, rate_limiter=kwargs.get("rate_limiter"))
        except Exception as e:
            return ProbeResult(probe="app_fingerprint", obs_id=None, signals={}, error=str(e))
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return ProbeResult(probe="app_fingerprint", obs_id=None, signals={},
                               error="invalid json from whatweb")
        if not isinstance(data, list) or not data:
            return ProbeResult(probe="app_fingerprint", obs_id=None, signals={})

        plugins = data[0].get("plugins", {})
        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "app_fingerprint", "plugins": plugins,
                        "host": data[0].get("target", "")},
        )
        signals: dict[str, list[dict]] = {"origin_server": [], "edge": [], "framework": []}
        for plugin, slot in _PLUGIN_SLOTS.items():
            if plugin in plugins:
                signals[slot].append({"src": "app_fingerprint", "value": plugin, "w": 0.5})
        return ProbeResult(probe="app_fingerprint", obs_id=obs_id, signals=signals)
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/tools/whatweb.py tests/test_stage2_whatweb_probe.py
git commit -m "feat(stage2): WhatWebProbe emits ProbeResult and plugin signals"
```

---

## Phase 3 — Pipeline wiring

### Task 3.1: Pass `asset_id`, `host`, `intensity` through `_run_stage`

**Files:**
- Modify: `workers/info_gathering/pipeline.py`
- Test: `tests/test_stage2_pipeline_wiring.py`

**Step 1: Write failing test**

```python
# tests/test_stage2_pipeline_wiring.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from workers.info_gathering.pipeline import Pipeline, Stage
from workers.info_gathering.fingerprint_aggregator import ProbeResult


class TestPipelineKwargs:
    @pytest.mark.anyio
    async def test_run_stage_passes_asset_id_host_intensity(self):
        pipeline = Pipeline(target_id=42, container_name="info_gathering")
        captured = {}

        class FakeTool:
            async def execute(self, **kwargs):
                captured.update(kwargs)
                return ProbeResult(probe="banner", obs_id=1, signals={})

        stage = Stage(name="web_server_fingerprint", section_id="4.1.2", tools=[FakeTool])
        target = MagicMock(id=42, base_domain="acme.com")
        with patch.object(pipeline, "_classify_pending_assets", new_callable=AsyncMock, return_value=0):
            await pipeline._run_stage(stage, target, asset_id=501, host="api.acme.com",
                                      intensity="medium",
                                      scope_manager=AsyncMock(_in_scope_patterns=set()),
                                      headers=None, rate_limiter=None)
        assert captured["asset_id"] == 501
        assert captured["host"] == "api.acme.com"
        assert captured["intensity"] == "medium"
        assert captured["target_id"] == 42
```

**Step 2: Run** → FAIL (current `_run_stage` doesn't accept those kwargs).

**Step 3: Update `_run_stage` and `run`**

```python
# workers/info_gathering/pipeline.py — replace _run_stage signature
async def _run_stage(
    self,
    stage: Stage,
    target,
    asset_id: int,
    host: str,
    intensity: str,
    scope_manager: ScopeManager,
    headers: dict | None = None,
    rate_limiter=None,
) -> list:
    tools = [cls() for cls in stage.tools]
    tasks = [
        tool.execute(
            target_id=self.target_id, asset_id=asset_id, host=host, intensity=intensity,
            scope_manager=scope_manager, headers=headers,
            container_name=self.container_name, rate_limiter=rate_limiter, target=target,
        )
        for tool in tools
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    classified = await self._classify_pending_assets(scope_manager)
    return [r for r in results if not isinstance(r, Exception)]
```

The `run()` method needs updating too — see Task 3.2.

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/pipeline.py tests/test_stage2_pipeline_wiring.py
git commit -m "feat(stage2): pipeline._run_stage accepts asset_id/host/intensity kwargs"
```

---

### Task 3.2: Pipeline preamble — resolve asset, read intensity, call aggregator

**Files:**
- Modify: `workers/info_gathering/pipeline.py`
- Test: `tests/test_stage2_pipeline_wiring.py` (extend)

**Step 1: Write failing test**

```python
class TestPipelinePreambleAndAggregation:
    @pytest.mark.anyio
    async def test_pipeline_resolves_asset_and_invokes_aggregator_for_stage2(self):
        from workers.info_gathering.fingerprint_aggregator import ProbeResult
        pipeline = Pipeline(target_id=42, container_name="info_gathering")
        target = MagicMock(id=42, base_domain="acme.com")
        playbook = {"workers": [{"name": "info_gathering", "stages": [
            {"name": "web_server_fingerprint", "enabled": True,
             "config": {"fingerprint_intensity": "high"}},
        ]}]}

        with patch.object(pipeline, "_resolve_subject_asset",
                          new_callable=AsyncMock, return_value=501) as ra:
            with patch("workers.info_gathering.pipeline.FingerprintAggregator") as Agg:
                inst = Agg.return_value
                inst.write_summary = AsyncMock(return_value=99)
                inst.emit_info_leaks = AsyncMock(return_value=[])
                with patch.object(pipeline, "_run_stage", new_callable=AsyncMock,
                                  return_value=[ProbeResult(probe="banner", obs_id=1, signals={})]):
                    with patch.object(pipeline, "_get_resume_stage", new_callable=AsyncMock, return_value=None):
                        with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                            with patch.object(pipeline, "_checkpoint_stage", new_callable=AsyncMock):
                                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                                    with patch("workers.info_gathering.pipeline.push_task",
                                               new_callable=AsyncMock):
                                        await pipeline.run(target, AsyncMock(_in_scope_patterns=set()),
                                                           playbook=playbook)
        ra.assert_called_once_with("acme.com")
        Agg.assert_called_once()
        kwargs = Agg.call_args.kwargs
        assert kwargs["intensity"] == "high"
        inst.write_summary.assert_awaited_once()
```

**Step 2: Run** → FAIL.

**Step 3: Implement preamble in `run()` and add helpers**

```python
# workers/info_gathering/pipeline.py — add to imports
from workers.info_gathering.fingerprint_aggregator import FingerprintAggregator, ProbeResult

# Add methods to Pipeline:
async def _resolve_subject_asset(self, host: str) -> int:
    """Resolve the subject Asset for the current pipeline run."""
    from workers.info_gathering.base_tool import InfoGatheringTool
    # Use a throwaway tool instance only for its helper method
    class _Helper(InfoGatheringTool):
        async def execute(self, target_id: int, **kwargs): ...
    helper = _Helper()
    target_obj = await self._fetch_target()
    return await helper.resolve_or_create_asset(
        self.target_id, host, base_domain=target_obj.base_domain,
    )

async def _fetch_target(self):
    from lib_webbh import get_session
    from lib_webbh.database import Target
    from sqlalchemy import select
    async with get_session() as session:
        stmt = select(Target).where(Target.id == self.target_id)
        return (await session.execute(stmt)).scalar_one()

def _get_intensity(self, playbook: dict | None) -> str:
    from lib_webbh.playbooks import get_worker_stages
    stages = get_worker_stages(playbook, "info_gathering") or []
    for s in stages:
        if s.get("name") == "web_server_fingerprint":
            return s.get("config", {}).get("fingerprint_intensity", "low")
    return "low"

def _select_host(self, target) -> str:
    return target.base_domain  # subdomain spawned runs override via run(host=...)
```

Replace `run()`:

```python
async def run(
    self, target, scope_manager: ScopeManager, headers: dict | None = None,
    playbook: dict | None = None, rate_limiter=None, host: str | None = None,
) -> None:
    host = host or self._select_host(target)
    asset_id = await self._resolve_subject_asset(host)
    intensity = self._get_intensity(playbook)

    completed_phase = await self._get_resume_stage()
    start_index = STAGE_INDEX[completed_phase] + 1 if completed_phase and completed_phase in STAGE_INDEX else 0

    stages = self._filter_stages(playbook)
    for stage in stages[start_index:]:
        self.log.info(f"Starting stage: {stage.name}")
        await self._update_phase(stage.name)
        results = await self._run_stage(
            stage, target, asset_id, host, intensity,
            scope_manager, headers, rate_limiter,
        )
        stats: dict = {"probes": len(results)}
        if stage.section_id == "4.1.2":
            agg = FingerprintAggregator(asset_id=asset_id, target_id=self.target_id, intensity=intensity)
            probe_results = [r for r in results if isinstance(r, ProbeResult)]
            summary_obs_id = await agg.write_summary(probe_results)
            raw = self._collect_raw_for_emission(probe_results)
            fingerprint = {slot: agg._score_slot(slot, probe_results) for slot in
                           ("origin_server", "framework", "edge", "waf")}
            vuln_ids = await agg.emit_info_leaks(fingerprint, raw)
            stats.update({"summary_written": summary_obs_id is not None, "vulns": len(vuln_ids)})

        self.log.info(f"Stage complete: {stage.name}", extra={"stats": stats})
        await push_task(f"events:{self.target_id}", {
            "event": "STAGE_COMPLETE", "stage": stage.name, "stats": stats,
        })
        await self._checkpoint_stage(stage.name)

    await self._mark_completed()
    await push_task(f"events:{self.target_id}", {
        "event": "PIPELINE_COMPLETE", "target_id": self.target_id,
    })

def _collect_raw_for_emission(self, results: list[ProbeResult]) -> dict:
    raw: dict = {}
    for r in results:
        if r.probe == "banner":
            raw["banner"] = r.signals.get("_raw", {})
        elif r.probe == "error_page":
            raw["error_page_404"] = {"obs_id": r.obs_id,
                                     "signature_match": next(
                                         (s["value"] + "-default-404"
                                          for slot in ("origin_server","framework")
                                          for s in r.signals.get(slot, [])
                                          if s["src"] == "error_page_signature"), None)}
    return raw
```

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/pipeline.py tests/test_stage2_pipeline_wiring.py
git commit -m "feat(stage2): pipeline preamble + aggregator invocation for stage 4.1.2"
```

---

### Task 3.3: Replace Stage 2 tool list in `STAGES`

**Files:**
- Modify: `workers/info_gathering/pipeline.py:44-55`
- Test: `tests/test_stage2_pipeline_wiring.py` (extend)

**Step 1: Write failing test**

```python
class TestStageRegistry:
    def test_stage2_tool_list_is_the_new_set(self):
        from workers.info_gathering.pipeline import STAGES
        names = [(s.name, s.section_id) for s in STAGES]
        assert ("web_server_fingerprint", "4.1.2") in names
        s = next(s for s in STAGES if s.name == "web_server_fingerprint")
        tool_names = {cls.__name__ for cls in s.tools}
        assert tool_names == {
            "LivenessProbe", "BannerProbe", "HeaderOrderProbe", "MethodProbe",
            "ErrorPageProbe", "TLSProbe", "WAFProbe", "WhatWeb",
        }
        # Nmap is no longer in Stage 2
        assert "Nmap" not in tool_names
```

**Step 2: Run** → FAIL.

**Step 3: Replace imports and STAGES entry for `web_server_fingerprint`**

```python
# workers/info_gathering/pipeline.py — replace existing Stage 2 imports + entry
from .tools.liveness_probe import LivenessProbe
from .tools.banner_probe import BannerProbe
from .tools.header_order_probe import HeaderOrderProbe
from .tools.method_probe import MethodProbe
from .tools.error_page_probe import ErrorPageProbe
from .tools.tls_probe import TLSProbe
from .tools.waf_probe import WAFProbe
# WhatWeb already imported

# In STAGES:
Stage(name="web_server_fingerprint", section_id="4.1.2", tools=[
    LivenessProbe, BannerProbe, HeaderOrderProbe, MethodProbe,
    ErrorPageProbe, TLSProbe, WAFProbe, WhatWeb,
]),
```

Leave `Nmap` import (still used by Stage 9 if applicable; otherwise remove import).

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add workers/info_gathering/pipeline.py tests/test_stage2_pipeline_wiring.py
git commit -m "feat(stage2): replace web_server_fingerprint tool list with new probes"
```

---

## Phase 4 — Playbook config and docker

### Task 4.1: Surface `fingerprint_intensity` in playbook builder

**Files:**
- Modify: `shared/lib_webbh/playbooks.py`
- Test: `tests/test_playbook_stage2_intensity.py` (create)

**Step 1: Write failing test**

```python
# tests/test_playbook_stage2_intensity.py
from lib_webbh.playbooks import get_worker_stages


def test_default_intensity_low_when_omitted():
    pb = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True},
    ]}]}
    stages = get_worker_stages(pb, "info_gathering")
    s = next(s for s in stages if s["name"] == "web_server_fingerprint")
    assert s.get("config", {}).get("fingerprint_intensity", "low") == "low"


def test_explicit_intensity_passes_through():
    pb = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True,
         "config": {"fingerprint_intensity": "high"}},
    ]}]}
    stages = get_worker_stages(pb, "info_gathering")
    s = next(s for s in stages if s["name"] == "web_server_fingerprint")
    assert s["config"]["fingerprint_intensity"] == "high"
```

**Step 2: Run** — Expected: PASS. This test locks the playbook shape we're already using. No code change to `playbooks.py` is required; the pipeline reads `config.fingerprint_intensity` (Task 3.2).

**Step 3: Commit**

```bash
git add tests/test_playbook_stage2_intensity.py
git commit -m "test(stage2): lock playbook fingerprint_intensity contract"
```

---

### Task 4.2: Install `tlsx` and `wafw00f` in info_gathering image

**Files:**
- Modify: `docker/Dockerfile.info_gathering`
- (No automated test — manual verification step)

**Step 1: Inspect current Dockerfile**

Run: `cat docker/Dockerfile.info_gathering`

**Step 2: Add tlsx + wafw00f installation**

Append after existing tool installs:

```dockerfile
# Stage 2 (WSTG-INFO-02) tooling
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
    && mv /root/go/bin/tlsx /usr/local/bin/tlsx
RUN pip install --no-cache-dir wafw00f==2.2.0
```

**Step 3: Verify by building**

Run: `docker build -f docker/Dockerfile.info_gathering -t test-stage2-image .`
Then: `docker run --rm test-stage2-image which tlsx wafw00f`
Expected: both paths printed.

**Step 4: Commit**

```bash
git add docker/Dockerfile.info_gathering
git commit -m "build(stage2): install tlsx and wafw00f in info_gathering image"
```

---

## Phase 5 — Integration tests

### Task 5.1: Stage 2 happy path against mocked Cloudflare target

**Files:**
- Create: `tests/test_info_gathering_stage2_integration.py`
- Create: `tests/fixtures/stage2/__init__.py`
- Create: `tests/fixtures/stage2/cloudflare_responses.py`

**Step 1: Write fixtures**

```python
# tests/fixtures/stage2/cloudflare_responses.py
CF_HEADERS = {
    "Server": "cloudflare",
    "X-Powered-By": "Express",
    "Set-Cookie": "__cf_bm=abc; path=/",
    "CF-RAY": "abc123-DFW",
    "Content-Type": "text/html",
}
CF_404_BODY = "<html>Cloudflare error... ray id abc123</html>"
TLSX_OUT = '{"host":"api.acme.com","ja3s_hash":"e7d705","tls_version":"tls13","issuer_cn":"Cloudflare Inc","subject_an":["*.acme.com"],"alpn":["h2","http/1.1"]}'
WAFW00F_OUT = '{"detected":true,"firewall":"Cloudflare"}'
HTTPX_OUT = '\n'.join([
    '{"url":"https://api.acme.com:443","port":"443","status_code":200,"tech":[]}',
    '{"url":"http://api.acme.com:80","port":"80","status_code":301,"tech":[]}',
])
```

**Step 2: Write failing integration test**

```python
# tests/test_info_gathering_stage2_integration.py
import pytest
from unittest.mock import AsyncMock, patch
from aioresponses import aioresponses
import re
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from lib_webbh.database import Base, Target, Asset, Observation, Location, Vulnerability
from tests.fixtures.stage2.cloudflare_responses import (
    CF_HEADERS, CF_404_BODY, TLSX_OUT, WAFW00F_OUT, HTTPX_OUT,
)


@pytest.fixture
async def engine(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def fake_session():
        async with Session() as s:
            yield s

    monkeypatch.setattr("lib_webbh.database.get_session", fake_session)
    monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_session)
    monkeypatch.setattr("workers.info_gathering.fingerprint_aggregator.get_session", fake_session, raising=False)
    yield engine
    await engine.dispose()


@pytest.mark.anyio
async def test_stage2_full_path_cloudflare_target(engine):
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as sess:
        t = Target(company_name="Acme", base_domain="acme.com")
        sess.add(t); await sess.commit(); await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="api.acme.com")
        sess.add(a); await sess.commit(); await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline
    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "web_server_fingerprint", "enabled": True,
         "config": {"fingerprint_intensity": "medium"}},
    ]}]}

    from unittest.mock import MagicMock
    target_obj = MagicMock(id=target_id, base_domain="acme.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    # Mock subprocess for httpx, tlsx, wafw00f
    async def fake_subprocess(cmd, **_):
        if cmd[0] == "httpx":   return HTTPX_OUT
        if cmd[0] == "tlsx":    return TLSX_OUT
        if cmd[0] == "wafw00f": return WAFW00F_OUT
        if cmd[0] == "whatweb": return '[{"target":"https://api.acme.com","plugins":{"Cloudflare":{}}}]'
        return ""

    pattern = re.compile(r"https://api\.acme\.com.*")
    with patch("workers.info_gathering.base_tool.InfoGatheringTool.run_subprocess",
               new=AsyncMock(side_effect=fake_subprocess)):
        with patch("workers.info_gathering.tools.header_order_probe.HeaderOrderProbe._raw_get",
                   new=AsyncMock(return_value="HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n")):
            with aioresponses() as m:
                m.get("https://api.acme.com/", status=200, body="", headers=CF_HEADERS, repeat=True)
                m.get(pattern, status=404, body=CF_404_BODY, repeat=True)
                m.options("https://api.acme.com/", status=200, headers={"Allow":"GET,HEAD,POST"}, repeat=True)
                m.head("https://api.acme.com/", status=200, headers={}, repeat=True)
                m.request("PROPFIND", "https://api.acme.com/", status=405, repeat=True)
                m.request("TRACE", "https://api.acme.com/", status=405, repeat=True)
                with patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
                    with patch.object(Pipeline, "_get_resume_stage", new=AsyncMock(return_value=None)):
                        with patch.object(Pipeline, "_update_phase", new=AsyncMock()):
                            with patch.object(Pipeline, "_checkpoint_stage", new=AsyncMock()):
                                with patch.object(Pipeline, "_mark_completed", new=AsyncMock()):
                                    with patch.object(Pipeline, "_classify_pending_assets",
                                                      new=AsyncMock(return_value=0)):
                                        await pipeline.run(target_obj, scope_manager, playbook=playbook,
                                                           host="api.acme.com")

    async with Session() as sess:
        obs = (await sess.execute(select(Observation).where(Observation.asset_id == asset_id))).scalars().all()
        probes = [o.tech_stack.get("_probe") for o in obs if o.tech_stack]
        assert "summary" in probes
        assert "banner" in probes
        assert "tls" in probes
        summary = next(o for o in obs if o.tech_stack.get("_probe") == "summary")
        assert summary.tech_stack["fingerprint"]["edge"]["vendor"] == "Cloudflare"
        locs = (await sess.execute(select(Location).where(Location.asset_id == asset_id))).scalars().all()
        assert {l.port for l in locs} >= {80, 443}
        vulns = (await sess.execute(select(Vulnerability).where(Vulnerability.asset_id == asset_id))).scalars().all()
        titles = {v.title for v in vulns}
        assert "Framework disclosure via X-Powered-By" in titles
```

**Step 2 (continued): Run** → FAIL initially.

**Step 3: Fix any wiring issues until PASS.**

**Step 4: Run** → PASS.

**Step 5: Commit**

```bash
git add tests/fixtures/stage2/ tests/test_info_gathering_stage2_integration.py
git commit -m "test(stage2): integration test for cloudflare-fronted target"
```

---

### Task 5.2: Additional integration tests (I2-I14 from design)

Repeat the Task 5.1 pattern for each remaining integration test in design §4.4 (I2 vanilla nginx, I3 locations dedup, I4 SSE, I5 resume, I6 rate-limit, I7 scope violation, I8 stage disabled, I9 method_quirks at high, I10 partial failure, I11 vuln evidence linkage, I12 idempotent resolution, I13 ip-typed asset, I14 default intensity).

Each integration test follows the same shape:

**Step 1:** Write the failing test in `tests/test_info_gathering_stage2_integration.py`.
**Step 2:** Run to confirm FAIL.
**Step 3:** Adjust implementation until PASS (often no change needed; the failure exposes a fixture problem).
**Step 4:** Confirm PASS.
**Step 5:** Commit.

Commits should be one per test, e.g. `test(stage2): I2 vanilla nginx target`.

---

## Phase 6 — Dashboard

### Task 6.1: Intensity selector with focus-revealed warning copy

**Files:**
- Modify: `dashboard/src/components/campaign/PlaybookSelector.tsx`
- Test: `dashboard/e2e/stage2-fingerprint.spec.ts` (create)

**Step 1: Read current PlaybookSelector to find where stage-level config lives**

Run: `grep -n "fingerprint\|web_server_fingerprint\|intensity" dashboard/src/components/campaign/PlaybookSelector.tsx`

**Step 2: Add intensity radio component**

In the stage card for `web_server_fingerprint`, render a small radio group:

```tsx
{stage.name === "web_server_fingerprint" && (
  <fieldset className="mt-2">
    <legend className="sr-only">Fingerprint intensity</legend>
    {(["low", "medium", "high"] as const).map((level) => (
      <label key={level} className="flex items-start gap-2 py-1">
        <input
          type="radio"
          name={`fp-intensity-${stage.name}`}
          value={level}
          checked={(stage.config?.fingerprint_intensity ?? "low") === level}
          onChange={() => updateStageConfig(stage.name, { fingerprint_intensity: level })}
          aria-describedby={`fp-${level}-help`}
        />
        <span>
          <span className="capitalize">{level}</span>
          {/* description rendered only when this level is selected/focused */}
          <span
            id={`fp-${level}-help`}
            role="note"
            className="block text-xs text-text-muted"
            hidden={(stage.config?.fingerprint_intensity ?? "low") !== level}
          >
            {INTENSITY_COPY[level]}
          </span>
        </span>
      </label>
    ))}
  </fieldset>
)}
```

At the top of the file:

```ts
const INTENSITY_COPY = {
  low: "Conservative probes that look like normal client variation. Safe against most production targets.",
  medium: "⚠️ Adds active WAF probing and uncommon HTTP methods (PROPFIND, TRACE, HTTP/0.9). May appear in IDS/WAF logs as suspicious. Use when target authorization clearly covers active reconnaissance.",
  high: "⚠️⚠️ Sends malformed methods, garbage verbs, and aggressive plugin checks. Will trigger WAFs, may be blocked, and is conspicuous to defenders. Only use against authorized targets with explicit go-ahead for noisy fingerprinting.",
} as const;
```

**Step 3: Write Playwright tests E1, E2, E8**

```ts
// dashboard/e2e/stage2-fingerprint.spec.ts
import { test, expect } from "@playwright/test";

test("E1 intensity selector renders three options with sequential warnings", async ({ page }) => {
  await page.goto("/campaign/new");
  await page.getByRole("button", { name: /web server fingerprint/i }).click();
  for (const [level, snippet] of [
    ["low", "Conservative probes"],
    ["medium", "Adds active WAF"],
    ["high", "Sends malformed methods"],
  ]) {
    await page.getByRole("radio", { name: new RegExp(level, "i") }).check();
    await expect(page.getByText(snippet, { exact: false })).toBeVisible();
  }
});

test("E2 selected intensity persists into playbook payload", async ({ page }) => {
  let captured: any = null;
  await page.route("**/api/v1/playbooks", async (route) => {
    captured = route.request().postDataJSON();
    await route.fulfill({ status: 201, body: JSON.stringify({ id: 1 }) });
  });
  await page.goto("/campaign/new");
  await page.getByRole("radio", { name: /medium/i }).check();
  await page.getByRole("button", { name: /save playbook/i }).click();
  const ig = captured.workers.find((w: any) => w.name === "info_gathering");
  const st = ig.stages.find((s: any) => s.name === "web_server_fingerprint");
  expect(st.config.fingerprint_intensity).toBe("medium");
});

test("E8 intensity warning text matches canonical strings", async ({ page }) => {
  await page.goto("/campaign/new");
  const expected = {
    low: "Conservative probes that look like normal client variation. Safe against most production targets.",
    medium: "⚠️ Adds active WAF probing and uncommon HTTP methods (PROPFIND, TRACE, HTTP/0.9). May appear in IDS/WAF logs as suspicious. Use when target authorization clearly covers active reconnaissance.",
    high: "⚠️⚠️ Sends malformed methods, garbage verbs, and aggressive plugin checks. Will trigger WAFs, may be blocked, and is conspicuous to defenders. Only use against authorized targets with explicit go-ahead for noisy fingerprinting.",
  };
  for (const [level, text] of Object.entries(expected)) {
    await page.getByRole("radio", { name: new RegExp(level, "i") }).check();
    await expect(page.getByText(text)).toBeVisible();
  }
});
```

**Step 4: Run**

```bash
cd dashboard && npm run test:e2e -- stage2-fingerprint.spec.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add dashboard/src/components/campaign/PlaybookSelector.tsx dashboard/e2e/stage2-fingerprint.spec.ts
git commit -m "feat(stage2,ui): intensity selector with focus-revealed warning copy"
```

---

### Task 6.2: Fingerprint panel in `AssetDetailDrawer`

**Files:**
- Modify: `dashboard/src/components/c2/AssetDetailDrawer.tsx`
- Create: `dashboard/src/components/c2/FingerprintPanel.tsx`
- Test: `dashboard/e2e/stage2-fingerprint.spec.ts` (extend with E3-E7)

**Step 1: Write failing Playwright tests E3-E7**

```ts
test("E3 fingerprint panel renders for asset with summary observation", async ({ page }) => {
  // Mock API to return a Cloudflare summary observation
  await page.route("**/api/v1/assets/501", async (route) => {
    await route.fulfill({ status: 200, body: JSON.stringify({
      id: 501, asset_type: "subdomain", asset_value: "api.acme.com",
      observations: [{ id: 1, tech_stack: {
        _probe: "summary", intensity: "low",
        fingerprint: {
          edge: { vendor: "Cloudflare", confidence: 0.99, signals: [] },
          origin_server: { vendor: null, confidence: 0, note: "masked by edge", signals: [] },
          framework: { vendor: "Express", confidence: 0.6, signals: [] },
          waf: { vendor: "Cloudflare", confidence: 0.99 },
        },
      }}],
    })});
  });
  await page.goto("/campaign/c2?asset=501");
  await expect(page.getByText(/Edge:\s*Cloudflare/i)).toBeVisible();
  await expect(page.getByText(/Framework:\s*Express/i)).toBeVisible();
});

// E4, E5, E6, E7 follow same shape — see design §4.5
```

**Step 2: Run** → FAIL.

**Step 3: Implement `FingerprintPanel.tsx` and wire into `AssetDetailDrawer`**

```tsx
// dashboard/src/components/c2/FingerprintPanel.tsx
"use client";
import { useState } from "react";

type Slot = { vendor: string | null; confidence: number; signals?: any[]; conflict?: boolean; note?: string; candidates?: any[] };
type Fingerprint = { edge: Slot; origin_server: Slot; framework: Slot; waf: Slot; tls?: any };

export function FingerprintPanel({ summary }: { summary: any }) {
  const fp: Fingerprint = summary.fingerprint;
  const [expanded, setExpanded] = useState(false);
  return (
    <section className="border-t border-border pt-3" data-testid="fingerprint-panel">
      <header className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Fingerprint</h3>
        {summary.partial && <span className="text-xs text-amber-500">Partial</span>}
      </header>
      <dl className="mt-2 grid grid-cols-2 gap-2 text-sm">
        <Chip label="Edge"     slot={fp.edge} />
        <Chip label="Origin"   slot={fp.origin_server} />
        <Chip label="Framework" slot={fp.framework} />
        <Chip label="WAF"      slot={fp.waf} />
      </dl>
      <button
        className="mt-2 text-xs text-accent underline"
        onClick={() => setExpanded(v => !v)}
        aria-expanded={expanded}
      >
        {expanded ? "Hide signals" : "View signals"}
      </button>
      {expanded && (
        <ul className="mt-2 space-y-1 text-xs text-text-muted">
          {(summary.raw_probe_obs_ids ?? []).map((id: number) => (
            <li key={id}>obs #{id}</li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Chip({ label, slot }: { label: string; slot: Slot }) {
  if (slot.conflict) {
    return (
      <div className="rounded border border-amber-500 px-2 py-1" data-testid={`slot-${label.toLowerCase()}`}>
        <span className="font-medium">{label}:</span> {slot.vendor} ⚠ conflict
        <ul className="mt-1 text-xs">
          {(slot.candidates ?? []).map((c: any, i: number) => (
            <li key={i}>{c.vendor} ({(c.confidence * 100).toFixed(0)}%)</li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <div className="rounded border border-border px-2 py-1" data-testid={`slot-${label.toLowerCase()}`}>
      <span className="font-medium">{label}:</span>{" "}
      {slot.vendor ?? <span className="text-text-muted">{slot.note ?? "—"}</span>}
      {slot.vendor && <span className="ml-1 text-xs text-text-muted">({(slot.confidence * 100).toFixed(0)}%)</span>}
    </div>
  );
}
```

In `AssetDetailDrawer.tsx` add:

```tsx
import { FingerprintPanel } from "./FingerprintPanel";
// inside the drawer body:
{(() => {
  const summary = asset.observations?.find((o: any) => o.tech_stack?._probe === "summary");
  return summary ? <FingerprintPanel summary={summary.tech_stack} /> : null;
})()}
```

**Step 4: Run all e2e specs → PASS.**

**Step 5: Commit**

```bash
git add dashboard/src/components/c2/FingerprintPanel.tsx dashboard/src/components/c2/AssetDetailDrawer.tsx dashboard/e2e/stage2-fingerprint.spec.ts
git commit -m "feat(stage2,ui): FingerprintPanel renders summary observation"
```

---

## Phase 7 — Final verification

### Task 7.1: Full test suite

**Step 1:** Run the entire test suite.
```bash
pytest -x -q
```
Expected: all tests pass.

**Step 2:** Run dashboard tests.
```bash
cd dashboard && npm run lint && npm run test:e2e
```
Expected: all checks pass.

**Step 3:** Quick smoke: spin up stack and run a single-target pipeline against an `httpbin.org`-style test host.
```bash
docker compose up --build orchestrator info_gathering postgres redis dashboard
# Create a target via the API at http://localhost:8001/api/v1/targets
# Watch SSE on /api/v1/stream/<target_id>
```
Expected: Stage 2 emits one `STAGE_COMPLETE` event with `stats.summary_written == true` and a `summary` Observation appears in the asset drawer.

**Step 4:** Manual verification checklist (design §4.6).

### Task 7.2: PR

```bash
gh pr create --title "Stage 2: WSTG-INFO-02 web server fingerprint" --body "$(cat <<'EOF'
## Summary
- New 8-probe Stage 2 pipeline aligned to OWASP WSTG-INFO-02
- Per-asset Observation linkage; fixes pre-existing save_observation signature misuse
- Configurable intensity (low/medium/high) with focus-revealed warnings
- FingerprintAggregator produces one summary Observation + INFO/LOW info-leak Vulns

## Test plan
- [ ] `pytest -q` green
- [ ] `npm run test:e2e` green (8 new specs)
- [ ] Manual: Cloudflare target → edge=Cloudflare ≥0.95
- [ ] Manual: vanilla nginx → origin=nginx with version
EOF
)"
```

---

## Notes on safety

- `intensity=high` is conspicuous; never default to it in any built-in playbook.
- The `_raw_get` socket call in `HeaderOrderProbe` disables cert verification intentionally — this probe targets servers with self-signed or expired certs too. The body is discarded; this is fingerprinting only.
- `wafw00f` and `tlsx` are not pinned to specific versions in the Dockerfile; if upstream changes JSON shape, the JSON parsing in `WAFProbe` / `TLSProbe` falls through to `error=...` rather than crashing the stage.
