# Subdomain Takeover Stage Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a new Stage 4 (subdomain_takeover) to the recon-core pipeline using subjack to detect dangling CNAME subdomain takeover vulnerabilities.

**Architecture:** New `SubjackTool` class following the input-file pattern (like Massdns/Naabu) — queries domains from DB, writes temp file, runs subjack, parses JSON output, inserts Observation + Alert rows for vulnerable subdomains. Pipeline grows from 6 to 7 stages.

**Tech Stack:** Python 3.10, subjack (Go binary), SQLAlchemy async, pytest, asyncio

---

### Task 1: Create SubjackTool unit tests

**Files:**
- Create: `tests/test_recon_tools_takeover.py`

**Step 1: Write the unit tests**

```python
import json
from unittest.mock import MagicMock
from workers.recon_core.concurrency import WeightClass


def test_subjack_is_light():
    from workers.recon_core.tools.subjack import SubjackTool
    assert SubjackTool.weight_class == WeightClass.LIGHT


def test_subjack_build_command():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    tool._input_file = "/tmp/domains.txt"
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert cmd[0] == "subjack"
    assert "-w" in cmd
    assert "/tmp/domains.txt" in cmd
    assert "-ssl" in cmd
    assert "-a" in cmd
    assert "/opt/fingerprints.json" in cmd


def test_subjack_parse_output_vulnerable():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    line1 = json.dumps({
        "subdomain": "blog.example.com",
        "vulnerable": True,
        "service": "github",
        "fingerprint": "There isn't a GitHub Pages site here.",
    })
    line2 = json.dumps({
        "subdomain": "shop.example.com",
        "vulnerable": True,
        "service": "shopify",
        "fingerprint": "Sorry, this shop is currently unavailable.",
    })
    output = f"{line1}\n{line2}\n"
    results = tool.parse_output(output)
    assert len(results) == 2
    assert results[0]["subdomain"] == "blog.example.com"
    assert results[0]["service"] == "github"
    assert results[0]["fingerprint"] == "There isn't a GitHub Pages site here."
    assert results[1]["subdomain"] == "shop.example.com"
    assert results[1]["service"] == "shopify"


def test_subjack_parse_output_not_vulnerable():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    line1 = json.dumps({
        "subdomain": "www.example.com",
        "vulnerable": False,
        "service": "",
        "fingerprint": "",
    })
    output = f"{line1}\n"
    results = tool.parse_output(output)
    assert len(results) == 0


def test_subjack_parse_output_empty():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    assert tool.parse_output("") == []
    assert tool.parse_output("  \n  \n") == []


def test_subjack_parse_output_malformed():
    from workers.recon_core.tools.subjack import SubjackTool
    tool = SubjackTool()
    output = "not json\n{broken\n"
    results = tool.parse_output(output)
    assert results == []
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_recon_tools_takeover.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'workers.recon_core.tools.subjack'`

**Step 3: Commit**

```bash
git add tests/test_recon_tools_takeover.py
git commit -m "test(recon-core): add SubjackTool unit tests (red)"
```

---

### Task 2: Implement SubjackTool

**Files:**
- Create: `workers/recon_core/tools/subjack.py`

**Step 1: Write the SubjackTool class**

Model after `workers/recon_core/tools/massdns.py` (input-file pattern) and `workers/recon_core/tools/httpx_tool.py` (Observation + custom execute).

```python
"""Subjack wrapper — subdomain takeover detection."""

import asyncio
import json
import os
import tempfile

from sqlalchemy import select

from lib_webbh import Asset, Alert, Observation, get_session, push_task, setup_logger

from workers.recon_core.base_tool import ReconTool
from workers.recon_core.concurrency import WeightClass, get_semaphore

FINGERPRINTS_PATH = os.environ.get(
    "SUBJACK_FINGERPRINTS", "/opt/fingerprints.json"
)


class SubjackTool(ReconTool):
    name = "subjack"
    weight_class = WeightClass.LIGHT

    def __init__(self):
        self._input_file: str | None = None

    def build_command(self, target, headers=None):
        return [
            "subjack", "-w", self._input_file or "/dev/null",
            "-t", "50", "-timeout", "30",
            "-o", "/dev/stdout", "-ssl",
            "-a", FINGERPRINTS_PATH,
        ]

    def parse_output(self, stdout):
        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("vulnerable"):
                    results.append({
                        "subdomain": data.get("subdomain", ""),
                        "service": data.get("service", ""),
                        "fingerprint": data.get("fingerprint", ""),
                    })
            except (json.JSONDecodeError, ValueError):
                continue
        return results

    async def execute(self, target, scope_manager, target_id, container_name, headers=None):
        """Override to write input file and insert Observation + Alert rows."""
        log = setup_logger("recon-tool").bind(target_id=target_id)

        # Query all discovered domains
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "domain",
            )
            result = await session.execute(stmt)
            domains = [row[0] for row in result.all()]

        if not domains:
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

        # Write temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(domains))
            self._input_file = f.name

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            cmd = self.build_command(target, headers)
            try:
                stdout = await self.run_subprocess(cmd)
            except (asyncio.TimeoutError, FileNotFoundError):
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            results = self.parse_output(stdout)
            new_count = 0

            for item in results:
                subdomain = item["subdomain"]
                service = item["service"]

                scope_result = scope_manager.is_in_scope(subdomain)
                if not scope_result.in_scope:
                    continue

                async with get_session() as session:
                    # Look up existing Asset
                    stmt = select(Asset).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == scope_result.normalized,
                    )
                    result = await session.execute(stmt)
                    asset = result.scalar_one_or_none()
                    if asset is None:
                        continue

                    # Insert Observation
                    obs = Observation(
                        asset_id=asset.id,
                        status_code=None,
                        page_title=f"Subdomain takeover: {service}",
                        tech_stack=["subjack:takeover"],
                        headers=None,
                    )
                    session.add(obs)
                    await session.flush()

                    # Insert critical Alert
                    alert = Alert(
                        target_id=target_id,
                        alert_type="critical",
                        message=f"Subdomain takeover possible: {subdomain} \u2192 {service} (CNAME dangling)",
                    )
                    session.add(alert)
                    await session.commit()
                    alert_id = alert.id

                # Push alert event to Redis
                await push_task(f"events:{target_id}", {
                    "event": "critical_alert",
                    "alert_id": alert_id,
                    "message": f"Subdomain takeover possible: {subdomain} \u2192 {service} (CNAME dangling)",
                })
                new_count += 1

            return {
                "found": len(results),
                "in_scope": new_count,
                "new": new_count,
                "skipped_cooldown": False,
            }
        finally:
            sem.release()
            if self._input_file and os.path.exists(self._input_file):
                os.unlink(self._input_file)
            self._input_file = None
```

**Step 2: Run unit tests to verify they pass**

Run: `python -m pytest tests/test_recon_tools_takeover.py -v`
Expected: 6 PASSED

**Step 3: Commit**

```bash
git add workers/recon_core/tools/subjack.py
git commit -m "feat(recon-core): add SubjackTool for subdomain takeover detection"
```

---

### Task 3: Wire SubjackTool into tools exports

**Files:**
- Modify: `workers/recon_core/tools/__init__.py`

**Step 1: Add SubjackTool import and export**

Add this import after line 15 (`from workers.recon_core.tools.webanalyze import Webanalyze`):
```python
from workers.recon_core.tools.subjack import SubjackTool
```

Add `"SubjackTool"` to `__all__` list. The full `__all__` becomes:
```python
__all__ = [
    "Subfinder", "Assetfinder", "Chaos", "AmassPassive", "AmassActive",
    "Sublist3r", "Knockpy",
    "Massdns", "HttpxTool",
    "SubjackTool",
    "Webanalyze",
    "Naabu",
    "Katana", "Hakrawler", "Waybackurls", "Gauplus", "Paramspider",
]
```

**Step 2: Verify import works**

Run: `python -c "from workers.recon_core.tools import SubjackTool; print('OK')"`
Expected: `OK`

**Step 3: Commit**

```bash
git add workers/recon_core/tools/__init__.py
git commit -m "feat(recon-core): export SubjackTool from tools package"
```

---

### Task 4: Update pipeline tests for 7 stages

**Files:**
- Modify: `tests/test_recon_pipeline.py`

**Step 1: Update `test_stages_defined_in_order` to expect 7 stages**

The existing test at `tests/test_recon_pipeline.py:11-19` asserts 6 stages with `"fingerprinting"` at index 3. Update to:

```python
def test_stages_defined_in_order():
    from workers.recon_core.pipeline import STAGES
    assert len(STAGES) == 7
    assert STAGES[0].name == "passive_discovery"
    assert STAGES[1].name == "active_discovery"
    assert STAGES[2].name == "liveness_dns"
    assert STAGES[3].name == "subdomain_takeover"
    assert STAGES[4].name == "fingerprinting"
    assert STAGES[5].name == "port_mapping"
    assert STAGES[6].name == "deep_recon"
```

**Step 2: Update `test_run_pipeline_skips_completed_stages`**

The existing test at line 37-55 asserts `mock_run.call_count == 4` and expects stages after `"active_discovery"`. With the new stage, it should be 5 calls:

```python
@pytest.mark.anyio
async def test_run_pipeline_skips_completed_stages():
    from workers.recon_core.pipeline import Pipeline

    pipeline = Pipeline(target_id=1, container_name="test-container")

    with patch.object(pipeline, "_get_completed_phase", return_value="active_discovery"):
        with patch.object(pipeline, "_run_stage", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"found": 0, "in_scope": 0, "new": 0}
            with patch.object(pipeline, "_update_phase", new_callable=AsyncMock):
                with patch.object(pipeline, "_mark_completed", new_callable=AsyncMock):
                    with patch("workers.recon_core.pipeline.push_task", new_callable=AsyncMock):
                        target = MagicMock(base_domain="example.com", target_profile={})
                        scope_mgr = MagicMock()

                        await pipeline.run(target, scope_mgr)

                        assert mock_run.call_count == 5
                        called_stages = [call.args[0].name for call in mock_run.call_args_list]
                        assert called_stages == [
                            "liveness_dns", "subdomain_takeover",
                            "fingerprinting", "port_mapping", "deep_recon",
                        ]
```

**Step 3: Run pipeline tests to verify they fail (pipeline not updated yet)**

Run: `python -m pytest tests/test_recon_pipeline.py -v`
Expected: FAIL — `assert 6 == 7` and stage order mismatch

**Step 4: Commit**

```bash
git add tests/test_recon_pipeline.py
git commit -m "test(recon-core): update pipeline tests for 7-stage layout (red)"
```

---

### Task 5: Update pipeline to add subdomain_takeover stage

**Files:**
- Modify: `workers/recon_core/pipeline.py:1` (docstring)
- Modify: `workers/recon_core/pipeline.py:15-32` (imports)
- Modify: `workers/recon_core/pipeline.py:43-50` (STAGES list)
- Modify: `workers/recon_core/pipeline.py:56` (Pipeline docstring)

**Step 1: Update the imports**

At `workers/recon_core/pipeline.py:15-32`, add `SubjackTool` to the import block:
```python
from workers.recon_core.tools import (
    Subfinder,
    Assetfinder,
    Chaos,
    AmassPassive,
    Sublist3r,
    Knockpy,
    AmassActive,
    Massdns,
    HttpxTool,
    SubjackTool,
    Webanalyze,
    Naabu,
    Katana,
    Hakrawler,
    Waybackurls,
    Gauplus,
    Paramspider,
)
```

**Step 2: Update the STAGES list**

At `workers/recon_core/pipeline.py:43-50`, insert the new stage at index 3:
```python
STAGES = [
    Stage("passive_discovery", [Subfinder, Assetfinder, Chaos, AmassPassive]),
    Stage("active_discovery", [Sublist3r, Knockpy, AmassActive]),
    Stage("liveness_dns", [Massdns, HttpxTool]),
    Stage("subdomain_takeover", [SubjackTool]),
    Stage("fingerprinting", [Webanalyze]),
    Stage("port_mapping", [Naabu]),
    Stage("deep_recon", [Katana, Hakrawler, Waybackurls, Gauplus, Paramspider]),
]
```

**Step 3: Update docstrings**

Line 1: `"""Recon pipeline: 7 sequential stages with checkpointing."""`
Line 56 (Pipeline docstring): `"""Orchestrates the 7-stage recon pipeline with checkpointing."""`

**Step 4: Run all pipeline and takeover tests**

Run: `python -m pytest tests/test_recon_pipeline.py tests/test_recon_tools_takeover.py -v`
Expected: ALL PASSED

**Step 5: Commit**

```bash
git add workers/recon_core/pipeline.py
git commit -m "feat(recon-core): add subdomain_takeover as new Stage 4 in pipeline"
```

---

### Task 6: Update Dockerfile

**Files:**
- Modify: `docker/Dockerfile.recon`

**Step 1: Add subjack to the Go builder stage**

At `docker/Dockerfile.recon:9-18`, add `subjack` to the `go install` chain. After the last `go install` line (webanalyze), add:
```
    go install github.com/haccer/subjack@latest
```

**Step 2: Copy subjack binary in runtime stage**

At `docker/Dockerfile.recon:43-52`, after the webanalyze COPY line, add:
```dockerfile
COPY --from=go-builder /go/bin/subjack /usr/local/bin/
```

**Step 3: Copy fingerprints.json**

After the Go binary COPY lines, add:
```dockerfile
COPY --from=go-builder /go/pkg/mod/github.com/haccer/subjack@*/fingerprints.json /opt/fingerprints.json
```

Note: The glob `@*` matches the installed version. If Docker build fails due to glob, use a two-step: `RUN cp /go/pkg/mod/github.com/haccer/subjack@*/fingerprints.json /opt/fingerprints.json` in the go-builder stage, then `COPY --from=go-builder /opt/fingerprints.json /opt/fingerprints.json` in runtime.

**Step 4: Commit**

```bash
git add docker/Dockerfile.recon
git commit -m "build(docker): add subjack binary and fingerprints to recon image"
```

---

### Task 7: Run full test suite and verify

**Files:** None (verification only)

**Step 1: Run all recon tests**

Run: `python -m pytest tests/test_recon_*.py -v`
Expected: ALL PASSED

**Step 2: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: ALL PASSED

**Step 3: Verify imports work end-to-end**

Run: `python -c "from workers.recon_core.pipeline import STAGES; print(f'{len(STAGES)} stages'); print([s.name for s in STAGES])"`
Expected:
```
7 stages
['passive_discovery', 'active_discovery', 'liveness_dns', 'subdomain_takeover', 'fingerprinting', 'port_mapping', 'deep_recon']
```

---

## Summary of Changes

| # | File | Action | Description |
|---|------|--------|-------------|
| 1 | `tests/test_recon_tools_takeover.py` | Create | Unit tests for SubjackTool |
| 2 | `workers/recon_core/tools/subjack.py` | Create | SubjackTool implementation |
| 3 | `workers/recon_core/tools/__init__.py` | Modify | Add SubjackTool export |
| 4 | `tests/test_recon_pipeline.py` | Modify | Update stage count/order assertions |
| 5 | `workers/recon_core/pipeline.py` | Modify | Add Stage 4 + import |
| 6 | `docker/Dockerfile.recon` | Modify | Add subjack binary + fingerprints |
