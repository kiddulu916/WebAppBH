# Phase 11 — Network Testing Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `network_worker` Docker worker that performs deep port enumeration, service fingerprinting, default credential testing, LDAP injection, and safe Metasploit exploit verification against non-HTTP network services.

**Architecture:** 4-stage pipeline (port_discovery → service_scan → credential_test → exploit_verify) following the established worker pattern. msfrpcd runs as a background daemon for structured MSF interaction via pymetasploit3. All results flow to `locations`, `observations`, and `vulnerabilities` tables.

**Tech Stack:** Python 3, asyncio, pymetasploit3, Nmap XML parsing, Kali Linux slim, Naabu, Medusa, Socat

**Design doc:** `docs/plans/design/2026-03-19-phase11-network-worker-design.md`

---

## Task 1: Scaffold Package & Concurrency Module

**Files:**
- Create: `workers/network_worker/__init__.py`
- Create: `workers/network_worker/concurrency.py`
- Test: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Create `tests/test_network_worker_tools.py`:

```python
"""Tests for network_worker tools."""

import os

import pytest

os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")


def test_network_worker_concurrency_weight_classes():
    from workers.network_worker.concurrency import WeightClass

    assert WeightClass.LIGHT.value == "light"
    assert WeightClass.MEDIUM.value == "medium"
    assert WeightClass.HEAVY.value == "heavy"


def test_network_worker_concurrency_get_semaphore():
    from workers.network_worker.concurrency import WeightClass, get_semaphore

    for wc in WeightClass:
        sem = get_semaphore(wc)
        assert sem is not None
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v`
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write the implementation**

Create `workers/network_worker/__init__.py` (empty file).

Create `workers/network_worker/concurrency.py`:

```python
"""Semaphore pools for network-worker tools."""

import asyncio
import os
from enum import Enum

_heavy: asyncio.BoundedSemaphore | None = None
_medium: asyncio.BoundedSemaphore | None = None
_light: asyncio.BoundedSemaphore | None = None


class WeightClass(Enum):
    HEAVY = "heavy"
    MEDIUM = "medium"
    LIGHT = "light"


def get_semaphores(
    force_new: bool = False,
) -> tuple[asyncio.BoundedSemaphore, asyncio.BoundedSemaphore, asyncio.BoundedSemaphore]:
    """Return (heavy, medium, light) semaphore tuple.

    Reads HEAVY_CONCURRENCY, MEDIUM_CONCURRENCY, LIGHT_CONCURRENCY from env.
    Defaults: heavy=1, medium=2, light=4.
    """
    global _heavy, _medium, _light
    if _heavy is None or _medium is None or _light is None or force_new:
        heavy_cap = int(os.environ.get("HEAVY_CONCURRENCY", "1"))
        medium_cap = int(os.environ.get("MEDIUM_CONCURRENCY", "2"))
        light_cap = int(os.environ.get("LIGHT_CONCURRENCY", "4"))
        _heavy = asyncio.BoundedSemaphore(heavy_cap)
        _medium = asyncio.BoundedSemaphore(medium_cap)
        _light = asyncio.BoundedSemaphore(light_cap)
    return _heavy, _medium, _light


def get_semaphore(weight: WeightClass) -> asyncio.BoundedSemaphore:
    """Return the semaphore for the given weight class."""
    heavy, medium, light = get_semaphores()
    if weight is WeightClass.HEAVY:
        return heavy
    if weight is WeightClass.MEDIUM:
        return medium
    return light
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v`
Expected: 2 PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/__init__.py workers/network_worker/concurrency.py tests/test_network_worker_tools.py
git commit -m "feat(network-worker): scaffold package with concurrency module"
```

---

## Task 2: Base Tool (`NetworkTestTool`)

**Files:**
- Create: `workers/network_worker/base_tool.py`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Add failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
def test_network_test_tool_is_abstract():
    import inspect
    from workers.network_worker.base_tool import NetworkTestTool

    assert inspect.isabstract(NetworkTestTool)


def test_network_test_tool_has_required_helpers():
    from workers.network_worker.base_tool import NetworkTestTool

    assert hasattr(NetworkTestTool, "run_subprocess")
    assert hasattr(NetworkTestTool, "check_cooldown")
    assert hasattr(NetworkTestTool, "update_tool_state")
    assert hasattr(NetworkTestTool, "_save_location")
    assert hasattr(NetworkTestTool, "_save_observation_tech_stack")
    assert hasattr(NetworkTestTool, "_save_vulnerability")
    assert hasattr(NetworkTestTool, "_load_oos_attacks")
    assert hasattr(NetworkTestTool, "_get_non_http_locations")


def test_load_oos_attacks_missing_file(tmp_path):
    from workers.network_worker.base_tool import NetworkTestTool

    class DummyTool(NetworkTestTool):
        name = "dummy"
        weight_class = None
        async def execute(self, *a, **kw):
            return {}

    tool = DummyTool()
    result = tool._load_oos_attacks_sync(str(tmp_path / "nonexistent"))
    assert result == []


def test_load_oos_attacks_reads_profile(tmp_path):
    import json
    from workers.network_worker.base_tool import NetworkTestTool

    class DummyTool(NetworkTestTool):
        name = "dummy"
        weight_class = None
        async def execute(self, *a, **kw):
            return {}

    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"oos_attacks": ["dos", "exploit/multi/handler"]}))

    tool = DummyTool()
    result = tool._load_oos_attacks_sync(str(profile))
    assert result == ["dos", "exploit/multi/handler"]
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "network_test_tool or load_oos"`
Expected: FAIL with import errors

**Step 3: Write the implementation**

Create `workers/network_worker/base_tool.py`:

```python
"""Abstract base class for network testing tool wrappers."""

from __future__ import annotations

import asyncio
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta

from sqlalchemy import select

from lib_webbh import (
    Alert,
    Asset,
    Identity,
    JobState,
    Location,
    Observation,
    Vulnerability,
    get_session,
    push_task,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.network_worker.concurrency import WeightClass

logger = setup_logger("network-test-tool")

TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "600"))
COOLDOWN_HOURS = int(os.environ.get("COOLDOWN_HOURS", "24"))

# Ports typically served by HTTP — excluded from network worker scope
HTTP_PORTS = {80, 443, 8080, 8443}


class NetworkTestTool(ABC):
    """Base class for all network testing tool wrappers.

    Subclasses must set ``name`` and ``weight_class`` class
    attributes and implement ``execute()``.
    """

    name: str
    weight_class: WeightClass

    @abstractmethod
    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        """Run the tool and return a stats dict."""

    # ------------------------------------------------------------------
    # Subprocess runner
    # ------------------------------------------------------------------

    async def run_subprocess(self, cmd: list[str], timeout: int = TOOL_TIMEOUT) -> str:
        """Run a command and return decoded stdout."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise

        return stdout_bytes.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Cooldown helpers
    # ------------------------------------------------------------------

    async def check_cooldown(self, target_id: int, container_name: str) -> bool:
        """Return True if this tool was completed within COOLDOWN_HOURS."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=COOLDOWN_HOURS)
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
                JobState.status == "COMPLETED",
                JobState.last_tool_executed == self.name,
                JobState.last_seen >= cutoff,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none() is not None

    async def update_tool_state(self, target_id: int, container_name: str) -> None:
        """Update JobState.last_tool_executed and last_seen for this tool."""
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.last_tool_executed = self.name
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _load_oos_attacks_sync(self, profile_path: str) -> list[str]:
        """Read oos_attacks list from profile JSON. Returns [] on error."""
        try:
            with open(profile_path, "r") as f:
                data = json.load(f)
            return data.get("oos_attacks", [])
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return []

    async def _load_oos_attacks(self, target_id: int) -> list[str]:
        """Load oos_attacks from shared/config/{target_id}/profile.json."""
        config_dir = os.environ.get("CONFIG_DIR", "shared/config")
        profile_path = os.path.join(config_dir, str(target_id), "profile.json")
        return self._load_oos_attacks_sync(profile_path)

    async def _get_non_http_locations(self, target_id: int) -> list[Location]:
        """Fetch Location rows for non-HTTP ports."""
        async with get_session() as session:
            stmt = select(Location).join(Asset).where(
                Asset.target_id == target_id,
                Location.state == "open",
                Location.port.notin_(HTTP_PORTS),
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def _get_locations_by_service(
        self, target_id: int, service_names: list[str]
    ) -> list[Location]:
        """Fetch Location rows matching specific service names."""
        from sqlalchemy import func

        async with get_session() as session:
            stmt = select(Location).join(Asset).where(
                Asset.target_id == target_id,
                Location.state == "open",
                func.lower(Location.service).in_([s.lower() for s in service_names]),
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    async def _save_location(
        self,
        asset_id: int,
        port: int,
        protocol: str = "tcp",
        service: str | None = None,
        state: str = "open",
    ) -> int:
        """Upsert a Location row. Returns location id."""
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
                existing.state = state
                await session.commit()
                return existing.id

            loc = Location(
                asset_id=asset_id,
                port=port,
                protocol=protocol,
                service=service,
                state=state,
            )
            session.add(loc)
            await session.flush()
            loc_id = loc.id
            await session.commit()
            return loc_id

    async def _save_observation_tech_stack(
        self,
        asset_id: int,
        tech_data: dict,
    ) -> int:
        """Upsert tech_stack JSON on the Observation for an asset."""
        async with get_session() as session:
            stmt = select(Observation).where(Observation.asset_id == asset_id)
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing is not None:
                merged = existing.tech_stack or {}
                merged.update(tech_data)
                existing.tech_stack = merged
                await session.commit()
                return existing.id

            obs = Observation(
                asset_id=asset_id,
                tech_stack=tech_data,
            )
            session.add(obs)
            await session.flush()
            obs_id = obs.id
            await session.commit()
            return obs_id

    async def _save_vulnerability(
        self,
        target_id: int,
        asset_id: int | None,
        severity: str,
        title: str,
        description: str,
        poc: str | None = None,
    ) -> int:
        """Insert a Vulnerability row and create an Alert for critical/high."""
        async with get_session() as session:
            vuln = Vulnerability(
                target_id=target_id,
                asset_id=asset_id,
                severity=severity,
                title=title,
                description=description,
                poc=poc,
                source_tool=self.name,
            )
            session.add(vuln)
            await session.flush()
            vuln_id = vuln.id
            await session.commit()

        if severity in ("critical", "high"):
            await self._create_alert(
                target_id,
                vuln_id,
                f"[{severity.upper()}] {title}",
            )

        return vuln_id

    async def _create_alert(
        self,
        target_id: int,
        vuln_id: int,
        message: str,
    ) -> None:
        """Write alert to DB and push to Redis for SSE."""
        logger.warning(f"ALERT: {message}")
        async with get_session() as session:
            alert = Alert(
                target_id=target_id,
                vulnerability_id=vuln_id,
                alert_type="critical",
                message=message,
            )
            session.add(alert)
            await session.commit()
            alert_id = alert.id

        await push_task(f"events:{target_id}", {
            "event": "critical_alert",
            "alert_id": alert_id,
            "vulnerability_id": vuln_id,
            "message": message,
        })

    async def _get_asset_ip(self, asset_id: int) -> str | None:
        """Get the asset_value (IP/domain) for a given asset_id."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(Asset.id == asset_id)
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            return row
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v`
Expected: All PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/base_tool.py tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add NetworkTestTool base class"
```

---

## Task 3: Wordlists & CVE Mappings

**Files:**
- Create: `workers/network_worker/wordlists/default_creds.yaml`
- Create: `workers/network_worker/mappings/cve_to_msf.yaml`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
def test_default_creds_yaml_loads():
    import yaml
    from pathlib import Path

    creds_path = Path(__file__).resolve().parent.parent / "workers" / "network_worker" / "wordlists" / "default_creds.yaml"
    with open(creds_path) as f:
        creds = yaml.safe_load(f)

    assert isinstance(creds, dict)
    assert "ssh" in creds
    assert "mysql" in creds
    assert "ftp" in creds
    for service, pairs in creds.items():
        assert isinstance(pairs, list)
        for pair in pairs:
            assert len(pair) == 2


def test_cve_to_msf_yaml_loads():
    import yaml
    from pathlib import Path

    map_path = Path(__file__).resolve().parent.parent / "workers" / "network_worker" / "mappings" / "cve_to_msf.yaml"
    with open(map_path) as f:
        mappings = yaml.safe_load(f)

    assert isinstance(mappings, dict)
    assert "CVE-2017-0144" in mappings
    for cve_id, info in mappings.items():
        assert "module" in info
        assert "service" in info
        assert "ports" in info
        assert isinstance(info["ports"], list)
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "yaml_loads"`
Expected: FAIL with FileNotFoundError

**Step 3: Write the config files**

Create `workers/network_worker/wordlists/default_creds.yaml`:

```yaml
ssh:
  - ["root", "root"]
  - ["admin", "admin"]
  - ["admin", "password"]
  - ["root", "toor"]

ftp:
  - ["anonymous", ""]
  - ["admin", "admin"]
  - ["ftp", "ftp"]

telnet:
  - ["admin", "admin"]
  - ["root", "root"]
  - ["root", "toor"]

mysql:
  - ["root", ""]
  - ["root", "root"]
  - ["root", "mysql"]

postgresql:
  - ["postgres", "postgres"]
  - ["postgres", ""]

redis:
  - ["", ""]

mongodb:
  - ["admin", "admin"]
  - ["admin", ""]

smb:
  - ["administrator", ""]
  - ["guest", ""]

ldap:
  - ["admin", "admin"]
  - ["cn=admin", "admin"]
```

Create `workers/network_worker/mappings/cve_to_msf.yaml`:

```yaml
CVE-2017-0144:
  module: exploit/windows/smb/ms17_010_eternalblue
  service: smb
  ports: [445]

CVE-2019-0708:
  module: exploit/windows/rdp/cve_2019_0708_bluekeep_rce
  service: rdp
  ports: [3389]

CVE-2014-0160:
  module: auxiliary/scanner/ssl/openssl_heartbleed
  service: ssl
  ports: [443, 8443, 993, 995]

CVE-2014-3566:
  module: auxiliary/scanner/ssl/poodle
  service: ssl
  ports: [443, 8443]

CVE-2015-3306:
  module: exploit/unix/ftp/proftpd_modcopy_exec
  service: ftp
  ports: [21]

CVE-2011-2523:
  module: exploit/unix/ftp/vsftpd_234_backdoor
  service: ftp
  ports: [21]

CVE-2017-7494:
  module: exploit/linux/samba/is_known_pipename
  service: smb
  ports: [445]

CVE-2020-1938:
  module: auxiliary/admin/http/tomcat_ghostcat
  service: ajp
  ports: [8009]

CVE-2015-1635:
  module: auxiliary/dos/http/ms15_034_ulonglongadd
  service: http
  ports: [80, 443]

CVE-2016-2183:
  module: auxiliary/scanner/ssl/sweet32
  service: ssl
  ports: [443]

CVE-2021-44228:
  module: exploit/multi/http/log4shell_header_injection
  service: java
  ports: [8080, 8443]

CVE-2019-11510:
  module: auxiliary/scanner/http/pulse_ssl_vpn_fread_check
  service: vpn
  ports: [443]

CVE-2020-0796:
  module: auxiliary/scanner/smb/smb_ms17_010
  service: smb
  ports: [445]

CVE-2018-15473:
  module: auxiliary/scanner/ssh/ssh_enumusers
  service: ssh
  ports: [22]

CVE-2021-41773:
  module: auxiliary/scanner/http/apache_normalize_path
  service: http
  ports: [80, 443]

CVE-2017-12617:
  module: exploit/multi/http/tomcat_jsp_upload_bypass
  service: http
  ports: [8080, 8443]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v -k "yaml_loads"`
Expected: 2 PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/wordlists/ workers/network_worker/mappings/ tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add default credentials and CVE-to-MSF mappings"
```

---

## Task 4: NaabuTool (Stage 1 — Port Discovery)

**Files:**
- Create: `workers/network_worker/tools/__init__.py`
- Create: `workers/network_worker/tools/naabu_tool.py`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
# ===================================================================
# NaabuTool tests
# ===================================================================

def test_naabu_tool_attributes():
    from workers.network_worker.tools.naabu_tool import NaabuTool
    from workers.network_worker.concurrency import WeightClass

    tool = NaabuTool()
    assert tool.name == "naabu"
    assert tool.weight_class == WeightClass.LIGHT


def test_naabu_tool_build_command():
    from workers.network_worker.tools.naabu_tool import NaabuTool

    tool = NaabuTool()
    cmd = tool.build_command("192.168.1.1")
    assert "naabu" in cmd
    assert "-host" in cmd
    assert "192.168.1.1" in cmd
    assert "-json" in cmd


def test_naabu_tool_parse_output():
    import json
    from workers.network_worker.tools.naabu_tool import NaabuTool

    tool = NaabuTool()
    lines = [
        json.dumps({"host": "192.168.1.1", "port": 22}),
        json.dumps({"host": "192.168.1.1", "port": 3306}),
        "",
        "some random log line",
    ]
    raw = "\n".join(lines)
    results = tool.parse_output(raw)
    assert len(results) == 2
    assert {"host": "192.168.1.1", "port": 22} in results
    assert {"host": "192.168.1.1", "port": 3306} in results


def test_naabu_tool_parse_output_empty():
    from workers.network_worker.tools.naabu_tool import NaabuTool

    tool = NaabuTool()
    assert tool.parse_output("") == []
    assert tool.parse_output("   ") == []
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "naabu"`
Expected: FAIL

**Step 3: Write the implementation**

Create `workers/network_worker/tools/__init__.py` (leave empty for now — will populate in Task 10).

Create `workers/network_worker/tools/naabu_tool.py`:

```python
"""NaabuTool -- Stage 1 fast port discovery."""

from __future__ import annotations

import json

from sqlalchemy import select

from lib_webbh import Asset, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("naabu-tool")

NAABU_TIMEOUT = 300


class NaabuTool(NetworkTestTool):
    """Fast SYN scan via naabu to discover open ports."""

    name = "naabu"
    weight_class = WeightClass.LIGHT

    def build_command(self, host: str) -> list[str]:
        """Build the naabu CLI command."""
        return [
            "naabu",
            "-host", host,
            "-json",
            "-silent",
            "-rate", "1000",
        ]

    def parse_output(self, raw: str) -> list[dict]:
        """Parse naabu JSON-lines output into list of {host, port} dicts."""
        if not raw.strip():
            return []
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if "host" in entry and "port" in entry:
                    results.append(entry)
            except json.JSONDecodeError:
                continue
        return results

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping naabu -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        # Get all IP/domain assets for this target
        async with get_session() as session:
            stmt = select(Asset).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["domain", "ip"]),
            )
            result = await session.execute(stmt)
            assets = list(result.scalars().all())

        if not assets:
            log.warning("No domain/ip assets found — skipping naabu")
            return stats

        for asset in assets:
            host = asset.asset_value
            scope_result = scope_manager.is_in_scope(host)
            if not scope_result.in_scope:
                log.debug(f"Skipping out-of-scope host: {host}")
                continue

            cmd = self.build_command(host)
            try:
                raw = await self.run_subprocess(cmd, timeout=NAABU_TIMEOUT)
            except Exception as exc:
                log.error(f"naabu failed for {host}: {exc}")
                continue

            entries = self.parse_output(raw)
            stats["found"] += len(entries)
            stats["in_scope"] += len(entries)

            for entry in entries:
                port = entry["port"]
                await self._save_location(
                    asset_id=asset.id,
                    port=port,
                    protocol="tcp",
                    state="open",
                )
                stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("naabu complete", extra=stats)
        return stats
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v -k "naabu"`
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/tools/ tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add NaabuTool for port discovery"
```

---

## Task 5: NmapTool (Stage 2 — Service Versioning)

**Files:**
- Create: `workers/network_worker/tools/nmap_tool.py`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
# ===================================================================
# NmapTool tests
# ===================================================================

def test_nmap_tool_attributes():
    from workers.network_worker.tools.nmap_tool import NmapTool
    from workers.network_worker.concurrency import WeightClass

    tool = NmapTool()
    assert tool.name == "nmap"
    assert tool.weight_class == WeightClass.MEDIUM


def test_nmap_tool_build_command():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    cmd = tool.build_command("192.168.1.1", [22, 80, 445])
    assert "nmap" in cmd
    assert "-sV" in cmd
    assert "-sC" in cmd
    assert "--script=vuln" in cmd
    assert "-oX" in cmd
    assert "-p" in cmd
    assert "22,80,445" in cmd


def test_nmap_tool_build_command_excludes_oos_scripts():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    cmd = tool.build_command("10.0.0.1", [445], oos_attacks=["smb-vuln-ms17-010", "dos"])
    cmd_str = " ".join(cmd)
    assert "exclude" in cmd_str.lower()


def test_nmap_tool_parse_xml_basic():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.2p2"/>
          </port>
          <port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="microsoft-ds" product="Samba"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 3.10 - 4.11" accuracy="98"/>
        </os>
      </host>
    </nmaprun>"""
    results = tool.parse_xml(xml)
    assert len(results) == 1
    host = results[0]
    assert host["addr"] == "192.168.1.1"
    assert len(host["ports"]) == 2
    assert host["ports"][0]["port"] == 22
    assert host["ports"][0]["service"] == "ssh"
    assert host["ports"][0]["product"] == "OpenSSH"
    assert host["ports"][0]["version"] == "7.2p2"
    assert host["os_match"] == "Linux 3.10 - 4.11"


def test_nmap_tool_extract_cves():
    from workers.network_worker.tools.nmap_tool import NmapTool

    tool = NmapTool()
    script_output = """
    smb-vuln-ms17-010:
      VULNERABLE:
      Remote Code Execution vulnerability in Microsoft SMBv1
        State: VULNERABLE
        IDs:  CVE:CVE-2017-0144
        Risk factor: HIGH
    heartbleed:
      VULNERABLE:
        IDs:  CVE:CVE-2014-0160
    """
    cves = tool.extract_cves(script_output)
    assert "CVE-2017-0144" in cves
    assert "CVE-2014-0160" in cves
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "nmap"`
Expected: FAIL

**Step 3: Write the implementation**

Create `workers/network_worker/tools/nmap_tool.py`:

```python
"""NmapTool -- Stage 2 deep service versioning and NSE vuln scanning."""

from __future__ import annotations

import os
import re
import tempfile
import xml.etree.ElementTree as ET

from sqlalchemy import select

from lib_webbh import Asset, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("nmap-tool")

NMAP_TIMEOUT = 600

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class NmapTool(NetworkTestTool):
    """Deep service versioning and NSE vulnerability scanning via nmap."""

    name = "nmap"
    weight_class = WeightClass.MEDIUM

    def build_command(
        self,
        host: str,
        ports: list[int],
        oos_attacks: list[str] | None = None,
        output_file: str = "-",
    ) -> list[str]:
        """Build the nmap CLI command."""
        port_str = ",".join(str(p) for p in ports)
        cmd = [
            "nmap", "-sV", "-sC",
            "--script=vuln",
            "-O",
            "-p", port_str,
            "-oX", output_file,
            host,
        ]
        if oos_attacks:
            exclude_str = ",".join(oos_attacks)
            cmd.insert(
                cmd.index("--script=vuln") + 1,
                f"--script-exclude={exclude_str}",
            )
        return cmd

    def parse_xml(self, xml_str: str) -> list[dict]:
        """Parse nmap XML output into structured host results."""
        results = []
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return results

        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            if addr_el is None:
                continue

            host_data = {
                "addr": addr_el.get("addr", ""),
                "ports": [],
                "os_match": None,
                "script_output": "",
            }

            # Parse ports
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    port_data = {
                        "port": int(port_el.get("portid", "0")),
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": state_el.get("state", "") if state_el is not None else "",
                        "service": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                    }

                    # Collect script output for this port
                    scripts = []
                    for script_el in port_el.findall("script"):
                        scripts.append(
                            f"{script_el.get('id', '')}: {script_el.get('output', '')}"
                        )
                    port_data["scripts"] = "\n".join(scripts)

                    host_data["ports"].append(port_data)

            # Parse OS detection
            os_el = host_el.find("os")
            if os_el is not None:
                osmatch = os_el.find("osmatch")
                if osmatch is not None:
                    host_data["os_match"] = osmatch.get("name", "")

            # Collect host-level script output
            hostscript_el = host_el.find("hostscript")
            if hostscript_el is not None:
                scripts = []
                for script_el in hostscript_el.findall("script"):
                    scripts.append(
                        f"{script_el.get('id', '')}: {script_el.get('output', '')}"
                    )
                host_data["script_output"] = "\n".join(scripts)

            results.append(host_data)

        return results

    def extract_cves(self, script_output: str) -> list[str]:
        """Extract CVE identifiers from NSE script output."""
        return list(set(_CVE_RE.findall(script_output)))

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping nmap -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}
        oos_attacks = kwargs.get("oos_attacks", [])

        # Get open locations from Stage 1
        locations = await self._get_non_http_locations(target_id)
        if not locations:
            log.info("No non-HTTP open ports to scan")
            return stats

        # Group ports by asset
        asset_ports: dict[int, list[int]] = {}
        for loc in locations:
            asset_ports.setdefault(loc.asset_id, []).append(loc.port)

        for asset_id, ports in asset_ports.items():
            host = await self._get_asset_ip(asset_id)
            if not host:
                continue

            scope_result = scope_manager.is_in_scope(host)
            if not scope_result.in_scope:
                continue

            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
                xml_path = tmp.name

            cmd = self.build_command(
                host, ports, oos_attacks=oos_attacks, output_file=xml_path,
            )

            try:
                await self.run_subprocess(cmd, timeout=NMAP_TIMEOUT)
                with open(xml_path) as f:
                    xml_str = f.read()
            except Exception as exc:
                log.error(f"nmap failed for {host}: {exc}")
                continue
            finally:
                try:
                    os.unlink(xml_path)
                except OSError:
                    pass

            hosts = self.parse_xml(xml_str)
            for host_data in hosts:
                for port_data in host_data["ports"]:
                    stats["found"] += 1
                    stats["in_scope"] += 1

                    service_str = port_data["service"]
                    if port_data["product"]:
                        service_str = port_data["product"]
                        if port_data["version"]:
                            service_str += f" {port_data['version']}"

                    await self._save_location(
                        asset_id=asset_id,
                        port=port_data["port"],
                        protocol=port_data["protocol"],
                        service=service_str,
                        state=port_data["state"],
                    )
                    stats["new"] += 1

                    # Extract CVEs from port scripts
                    all_scripts = port_data.get("scripts", "")
                    cves = self.extract_cves(all_scripts)
                    for cve in cves:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"Vulnerable Service — {cve}",
                            description=(
                                f"{service_str} on port {port_data['port']} "
                                f"flagged by NSE"
                            ),
                            poc=all_scripts[:2000],
                        )

                # Save OS fingerprint to observations
                if host_data.get("os_match"):
                    await self._save_observation_tech_stack(asset_id, {
                        "os_fingerprint": host_data["os_match"],
                        "nmap_scan_source": self.name,
                    })

                # Extract CVEs from host-level scripts
                if host_data.get("script_output"):
                    host_cves = self.extract_cves(host_data["script_output"])
                    for cve in host_cves:
                        await self._save_vulnerability(
                            target_id=target_id,
                            asset_id=asset_id,
                            severity="medium",
                            title=f"Host Vulnerability — {cve}",
                            description=(
                                f"Host-level NSE detection on "
                                f"{host_data['addr']}"
                            ),
                            poc=host_data["script_output"][:2000],
                        )

        await self.update_tool_state(target_id, container_name)
        log.info("nmap complete", extra=stats)
        return stats
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v -k "nmap"`
Expected: All PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/tools/nmap_tool.py tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add NmapTool for service versioning and NSE scanning"
```

---

## Task 6: BannerGrabTool (Stage 2 — LDAP Detection)

**Files:**
- Create: `workers/network_worker/tools/banner_grab_tool.py`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
# ===================================================================
# BannerGrabTool tests
# ===================================================================

def test_banner_grab_tool_attributes():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool
    from workers.network_worker.concurrency import WeightClass

    tool = BannerGrabTool()
    assert tool.name == "banner_grab"
    assert tool.weight_class == WeightClass.LIGHT


def test_banner_grab_tool_detect_ldap():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool

    tool = BannerGrabTool()
    assert tool.detect_service("0\x84") == "ldap"
    assert tool.detect_service("objectClass: top") == "ldap"
    assert tool.detect_service("LDAP") == "ldap"


def test_banner_grab_tool_detect_other_services():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool

    tool = BannerGrabTool()
    assert tool.detect_service("SSH-2.0-OpenSSH_7.2p2") == "ssh"
    assert tool.detect_service("220 ProFTPD 1.3.5") == "ftp"
    assert tool.detect_service("+OK POP3 server ready") == "pop3"
    assert tool.detect_service("* OK IMAP server ready") == "imap"
    assert tool.detect_service("220 mail.example.com ESMTP") == "smtp"


def test_banner_grab_tool_detect_unknown():
    from workers.network_worker.tools.banner_grab_tool import BannerGrabTool

    tool = BannerGrabTool()
    assert tool.detect_service("") is None
    assert tool.detect_service("some random binary data") is None
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "banner_grab"`
Expected: FAIL

**Step 3: Write the implementation**

Create `workers/network_worker/tools/banner_grab_tool.py`:

```python
"""BannerGrabTool -- Stage 2 raw banner grab for service identification."""

from __future__ import annotations

import re

from lib_webbh import get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("banner-grab-tool")

SOCAT_TIMEOUT = 10

# Banner patterns for service detection
_SERVICE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh", re.compile(r"^SSH-", re.IGNORECASE)),
    ("ftp", re.compile(
        r"^220[- ].*ftp|^220[- ].*ProFTPD|^220[- ].*vsftpd",
        re.IGNORECASE,
    )),
    ("smtp", re.compile(
        r"^220[- ].*ESMTP|^220[- ].*SMTP|^220[- ].*mail",
        re.IGNORECASE,
    )),
    ("pop3", re.compile(r"^\+OK.*POP3", re.IGNORECASE)),
    ("imap", re.compile(r"^\*\s*OK.*IMAP", re.IGNORECASE)),
    ("ldap", re.compile(r"LDAP|objectClass|0\x84|dn:|cn=", re.IGNORECASE)),
    ("mysql", re.compile(r"mysql|MariaDB", re.IGNORECASE)),
    ("redis", re.compile(r"^\-ERR|^-NOAUTH|^\+PONG|redis", re.IGNORECASE)),
]


class BannerGrabTool(NetworkTestTool):
    """Raw banner grab via socat to identify unrecognized services."""

    name = "banner_grab"
    weight_class = WeightClass.LIGHT

    def detect_service(self, banner: str) -> str | None:
        """Detect service type from a raw banner string."""
        if not banner or not banner.strip():
            return None
        for service_name, pattern in _SERVICE_PATTERNS:
            if pattern.search(banner):
                return service_name
        return None

    def build_command(self, host: str, port: int) -> list[str]:
        """Build socat command for banner grabbing."""
        return [
            "socat", "-T", str(SOCAT_TIMEOUT),
            "-", f"TCP:{host}:{port},connect-timeout={SOCAT_TIMEOUT}",
        ]

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping banner_grab -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        # Get locations with no service identified (or generic service)
        locations = await self._get_non_http_locations(target_id)
        unidentified = [
            loc for loc in locations
            if not loc.service or loc.service in ("unknown", "tcpwrapped", "")
        ]

        # Also always probe ports 389 and 636 even if Nmap set a service
        ldap_ports = {389, 636}
        ldap_locs = [
            loc for loc in locations
            if loc.port in ldap_ports and loc not in unidentified
        ]
        targets = unidentified + ldap_locs

        if not targets:
            log.info("No unidentified services to banner-grab")
            return stats

        for loc in targets:
            host = await self._get_asset_ip(loc.asset_id)
            if not host:
                continue

            cmd = self.build_command(host, loc.port)
            try:
                banner = await self.run_subprocess(cmd, timeout=SOCAT_TIMEOUT + 5)
            except Exception:
                continue

            detected = self.detect_service(banner)
            if detected:
                stats["found"] += 1
                stats["in_scope"] += 1
                await self._save_location(
                    asset_id=loc.asset_id,
                    port=loc.port,
                    protocol=loc.protocol or "tcp",
                    service=detected,
                    state="open",
                )
                stats["new"] += 1

        await self.update_tool_state(target_id, container_name)
        log.info("banner_grab complete", extra=stats)
        return stats
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v -k "banner_grab"`
Expected: All PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/tools/banner_grab_tool.py tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add BannerGrabTool for LDAP detection"
```

---

## Task 7: MedusaTool (Stage 3 — Credential Testing)

**Files:**
- Create: `workers/network_worker/tools/medusa_tool.py`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
# ===================================================================
# MedusaTool tests
# ===================================================================

def test_medusa_tool_attributes():
    from workers.network_worker.tools.medusa_tool import MedusaTool
    from workers.network_worker.concurrency import WeightClass

    tool = MedusaTool()
    assert tool.name == "medusa"
    assert tool.weight_class == WeightClass.MEDIUM


def test_medusa_tool_build_command():
    from workers.network_worker.tools.medusa_tool import MedusaTool

    tool = MedusaTool()
    cmd = tool.build_command("10.0.0.1", 22, "ssh", "admin", "admin")
    assert "medusa" in cmd
    assert "-h" in cmd
    assert "10.0.0.1" in cmd
    assert "-n" in cmd
    assert "22" in cmd
    # Rate limiting flags
    assert "-t" in cmd
    assert "-w" in cmd


def test_medusa_tool_parse_output_success():
    from workers.network_worker.tools.medusa_tool import MedusaTool

    tool = MedusaTool()
    raw = """
    ACCOUNT CHECK: [ssh] Host: 10.0.0.1 (1 of 1) User: admin Password: admin
    ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: admin Password: admin [SUCCESS]
    """
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["user"] == "admin"
    assert results[0]["password"] == "admin"


def test_medusa_tool_parse_output_no_success():
    from workers.network_worker.tools.medusa_tool import MedusaTool

    tool = MedusaTool()
    raw = """
    ACCOUNT CHECK: [ssh] Host: 10.0.0.1 User: admin Password: admin
    """
    results = tool.parse_output(raw)
    assert results == []


def test_medusa_tool_service_mapping():
    from workers.network_worker.tools.medusa_tool import SERVICE_TO_MEDUSA_MODULE

    assert "ssh" in SERVICE_TO_MEDUSA_MODULE
    assert "ftp" in SERVICE_TO_MEDUSA_MODULE
    assert "mysql" in SERVICE_TO_MEDUSA_MODULE
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "medusa"`
Expected: FAIL

**Step 3: Write the implementation**

Create `workers/network_worker/tools/medusa_tool.py`:

```python
"""MedusaTool -- Stage 3 default credential testing."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from lib_webbh import get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("medusa-tool")

MEDUSA_TIMEOUT = 120

_SUCCESS_RE = re.compile(
    r"ACCOUNT FOUND:.*Host:\s*(\S+).*User:\s*(\S+).*Password:\s*(\S+).*\[SUCCESS\]"
)

# Map service names (from nmap/banner_grab) to Medusa module names
SERVICE_TO_MEDUSA_MODULE: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "telnet": "telnet",
    "mysql": "mysql",
    "postgresql": "postgres",
    "redis": "redis",
    "mongodb": "mongodb",
    "smb": "smbnt",
    "microsoft-ds": "smbnt",
    "pop3": "pop3",
    "imap": "imap",
}

WORDLISTS_DIR = Path(__file__).resolve().parent.parent / "wordlists"


class MedusaTool(NetworkTestTool):
    """Default credential testing via Medusa with strict rate limiting."""

    name = "medusa"
    weight_class = WeightClass.MEDIUM

    def _load_creds(self, service: str) -> list[tuple[str, str]]:
        """Load credential pairs for a service from YAML."""
        creds_path = WORDLISTS_DIR / "default_creds.yaml"
        try:
            with open(creds_path) as f:
                all_creds = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            return []
        pairs = all_creds.get(service, [])
        return [(p[0], p[1]) for p in pairs if len(p) == 2]

    def build_command(
        self,
        host: str,
        port: int,
        module: str,
        user: str,
        password: str,
    ) -> list[str]:
        """Build the medusa CLI command with hardcoded rate limiting."""
        return [
            "medusa",
            "-h", host,
            "-n", str(port),
            "-u", user,
            "-p", password,
            "-M", module,
            "-t", "1",      # single thread — hardcoded safety
            "-w", "2",      # 2-second wait — hardcoded safety
            "-f",           # stop on first success
        ]

    def parse_output(self, raw: str) -> list[dict]:
        """Parse Medusa output for successful logins."""
        results = []
        for match in _SUCCESS_RE.finditer(raw):
            results.append({
                "host": match.group(1),
                "user": match.group(2),
                "password": match.group(3),
            })
        return results

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping medusa -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        locations = await self._get_non_http_locations(target_id)
        if not locations:
            log.info("No non-HTTP services to test credentials against")
            return stats

        for loc in locations:
            service = (loc.service or "").lower().split()[0]
            medusa_module = SERVICE_TO_MEDUSA_MODULE.get(service)
            if not medusa_module:
                continue

            host = await self._get_asset_ip(loc.asset_id)
            if not host:
                continue

            creds = self._load_creds(service)
            if not creds:
                creds = self._load_creds(medusa_module)
            if not creds:
                continue

            for user, password in creds:
                cmd = self.build_command(host, loc.port, medusa_module, user, password)
                try:
                    raw = await self.run_subprocess(cmd, timeout=MEDUSA_TIMEOUT)
                except Exception as exc:
                    log.error(f"medusa failed for {host}:{loc.port}: {exc}")
                    continue

                successes = self.parse_output(raw)
                for success in successes:
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=loc.asset_id,
                        severity="high",
                        title=(
                            f"Default Credentials — {service} "
                            f"on port {loc.port}"
                        ),
                        description=(
                            f"Successful login with "
                            f"{success['user']}:{success['password']} "
                            f"on {host}:{loc.port} ({service})"
                        ),
                        poc=(
                            f"medusa -h {host} -n {loc.port} "
                            f"-u {success['user']} -p {success['password']} "
                            f"-M {medusa_module}"
                        ),
                    )

                if successes:
                    break  # Found valid creds, stop testing this service

        await self.update_tool_state(target_id, container_name)
        log.info("medusa complete", extra=stats)
        return stats
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v -k "medusa"`
Expected: All PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/tools/medusa_tool.py tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add MedusaTool for default credential testing"
```

---

## Task 8: LdapInjectionTool (Stage 3 — LDAP Injection)

**Files:**
- Create: `workers/network_worker/tools/ldap_injection_tool.py`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
# ===================================================================
# LdapInjectionTool tests
# ===================================================================

def test_ldap_injection_tool_attributes():
    from workers.network_worker.tools.ldap_injection_tool import LdapInjectionTool
    from workers.network_worker.concurrency import WeightClass

    tool = LdapInjectionTool()
    assert tool.name == "ldap_injection"
    assert tool.weight_class == WeightClass.MEDIUM


def test_ldap_injection_payloads_exist():
    from workers.network_worker.tools.ldap_injection_tool import LDAP_PAYLOADS

    assert len(LDAP_PAYLOADS) > 0
    for payload in LDAP_PAYLOADS:
        assert "name" in payload
        assert "filter" in payload
        assert "category" in payload


def test_ldap_injection_categories():
    from workers.network_worker.tools.ldap_injection_tool import LDAP_PAYLOADS

    categories = {p["category"] for p in LDAP_PAYLOADS}
    assert "filter_manipulation" in categories
    assert "auth_bypass" in categories
    assert "data_extraction" in categories


def test_ldap_injection_classify_finding():
    from workers.network_worker.tools.ldap_injection_tool import LdapInjectionTool

    tool = LdapInjectionTool()
    assert tool.classify_severity("auth_bypass") == "high"
    assert tool.classify_severity("data_extraction") == "medium"
    assert tool.classify_severity("filter_manipulation") == "medium"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "ldap_injection"`
Expected: FAIL

**Step 3: Write the implementation**

Create `workers/network_worker/tools/ldap_injection_tool.py`:

```python
"""LdapInjectionTool -- Stage 3 LDAP filter injection testing."""

from __future__ import annotations

import asyncio
import time

from lib_webbh import get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("ldap-injection-tool")

LDAP_TIMEOUT = 30
INJECTION_DELAY = 1.0  # seconds between payloads

# LDAP injection payloads — read-only, no write/delete operations
LDAP_PAYLOADS: list[dict] = [
    # Filter manipulation
    {
        "name": "wildcard_uid",
        "filter": "*)(uid=*",
        "category": "filter_manipulation",
        "description": "LDAP filter manipulation via wildcard UID injection",
    },
    {
        "name": "wildcard_cn",
        "filter": ")(cn=*",
        "category": "filter_manipulation",
        "description": "LDAP filter manipulation via wildcard CN injection",
    },
    {
        "name": "always_true",
        "filter": "*)(objectClass=*",
        "category": "filter_manipulation",
        "description": "LDAP filter bypass via always-true objectClass wildcard",
    },
    # Auth bypass
    {
        "name": "auth_bypass_and",
        "filter": "*)(&",
        "category": "auth_bypass",
        "description": "LDAP authentication bypass via AND operator injection",
    },
    {
        "name": "auth_bypass_or",
        "filter": "*)(|(&",
        "category": "auth_bypass",
        "description": "LDAP authentication bypass via OR operator injection",
    },
    {
        "name": "auth_bypass_null",
        "filter": "*)(%00",
        "category": "auth_bypass",
        "description": "LDAP authentication bypass via null byte injection",
    },
    # Data extraction
    {
        "name": "extract_all_users",
        "filter": "*)(uid=*))(|(uid=*",
        "category": "data_extraction",
        "description": "LDAP data extraction via nested filter for all UIDs",
    },
    {
        "name": "extract_admin",
        "filter": "admin*)(|(objectClass=*",
        "category": "data_extraction",
        "description": "LDAP data extraction targeting admin accounts",
    },
]


class LdapInjectionTool(NetworkTestTool):
    """LDAP filter injection testing against detected LDAP services."""

    name = "ldap_injection"
    weight_class = WeightClass.MEDIUM

    def classify_severity(self, category: str) -> str:
        """Map payload category to vulnerability severity."""
        if category == "auth_bypass":
            return "high"
        return "medium"

    def _build_ldapsearch_command(
        self,
        host: str,
        port: int,
        payload_filter: str,
    ) -> list[str]:
        """Build ldapsearch command to test injection."""
        return [
            "ldapsearch",
            "-x",                     # simple auth
            "-H", f"ldap://{host}:{port}",
            "-b", "",                 # empty base DN
            "-s", "base",            # base scope only
            f"({payload_filter})",
            "-LLL",
            "-z", "1",              # limit results
        ]

    def _is_successful_injection(
        self,
        stdout: str,
        elapsed: float,
        payload: dict,
    ) -> bool:
        """Determine if an injection attempt was successful."""
        stdout_lower = stdout.lower()

        # Check for data returned (indicates filter worked)
        if any(
            marker in stdout_lower
            for marker in ["dn:", "cn=", "uid=", "objectclass:"]
        ):
            return True

        # Blind injection: significant timing difference
        if payload["category"] == "auth_bypass" and elapsed > 3.0:
            return True

        return False

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping ldap_injection -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}

        # Find LDAP services
        ldap_locations = await self._get_locations_by_service(
            target_id, ["ldap", "ldaps"]
        )
        if not ldap_locations:
            log.info("No LDAP services detected — skipping injection tests")
            return stats

        for loc in ldap_locations:
            host = await self._get_asset_ip(loc.asset_id)
            if not host:
                continue

            for payload in LDAP_PAYLOADS:
                cmd = self._build_ldapsearch_command(
                    host, loc.port, payload["filter"],
                )

                start = time.monotonic()
                try:
                    stdout = await self.run_subprocess(cmd, timeout=LDAP_TIMEOUT)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
                elapsed = time.monotonic() - start

                if self._is_successful_injection(stdout, elapsed, payload):
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1

                    severity = self.classify_severity(payload["category"])
                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=loc.asset_id,
                        severity=severity,
                        title=f"LDAP Injection — {payload['name']}",
                        description=payload["description"],
                        poc=(
                            f"Filter: ({payload['filter']})\n"
                            f"Host: {host}:{loc.port}\n"
                            f"Response: {stdout[:1000]}"
                        ),
                    )

                # Rate limit between payloads
                await asyncio.sleep(INJECTION_DELAY)

        await self.update_tool_state(target_id, container_name)
        log.info("ldap_injection complete", extra=stats)
        return stats
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v -k "ldap_injection"`
Expected: All PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/tools/ldap_injection_tool.py tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add LdapInjectionTool for LDAP filter injection"
```

---

## Task 9: MsfCheckTool (Stage 4 — Exploit Verification)

**Files:**
- Create: `workers/network_worker/tools/msf_check_tool.py`
- Modify: `tests/test_network_worker_tools.py`

**Step 1: Write the failing tests**

Append to `tests/test_network_worker_tools.py`:

```python
# ===================================================================
# MsfCheckTool tests
# ===================================================================

def test_msf_check_tool_attributes():
    from workers.network_worker.tools.msf_check_tool import MsfCheckTool
    from workers.network_worker.concurrency import WeightClass

    tool = MsfCheckTool()
    assert tool.name == "msf_check"
    assert tool.weight_class == WeightClass.HEAVY


def test_msf_check_tool_load_mappings():
    from workers.network_worker.tools.msf_check_tool import MsfCheckTool

    tool = MsfCheckTool()
    mappings = tool._load_mappings()
    assert isinstance(mappings, dict)
    assert "CVE-2017-0144" in mappings
    assert mappings["CVE-2017-0144"]["module"] == "exploit/windows/smb/ms17_010_eternalblue"


def test_msf_check_tool_find_modules_for_cves():
    from workers.network_worker.tools.msf_check_tool import MsfCheckTool

    tool = MsfCheckTool()
    cves = ["CVE-2017-0144", "CVE-9999-0000", "CVE-2019-0708"]
    matches = tool.find_modules_for_cves(cves)
    assert len(matches) == 2
    assert any(m["cve"] == "CVE-2017-0144" for m in matches)
    assert any(m["cve"] == "CVE-2019-0708" for m in matches)


def test_msf_check_tool_respects_oos():
    from workers.network_worker.tools.msf_check_tool import MsfCheckTool

    tool = MsfCheckTool()
    cves = ["CVE-2017-0144", "CVE-2019-0708"]
    oos = ["exploit/windows/smb/ms17_010_eternalblue"]
    matches = tool.find_modules_for_cves(cves, oos_attacks=oos)
    assert len(matches) == 1
    assert matches[0]["cve"] == "CVE-2019-0708"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_tools.py -v -k "msf_check"`
Expected: FAIL

**Step 3: Write the implementation**

Create `workers/network_worker/tools/msf_check_tool.py`:

```python
"""MsfCheckTool -- Stage 4 safe exploit verification via Metasploit check."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from sqlalchemy import select

from lib_webbh import Asset, Vulnerability, get_session, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.concurrency import WeightClass

logger = setup_logger("msf-check-tool")

MSFRPC_HOST = os.environ.get("MSFRPC_HOST", "127.0.0.1")
MSFRPC_PORT = int(os.environ.get("MSFRPC_PORT", "55553"))
MSFRPC_PASS = os.environ.get("MSFRPC_PASS", "msf_internal")

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class MsfCheckTool(NetworkTestTool):
    """Safe exploit verification using Metasploit's check command only."""

    name = "msf_check"
    weight_class = WeightClass.HEAVY

    def _load_mappings(self) -> dict:
        """Load CVE-to-MSF module mappings from YAML."""
        map_path = MAPPINGS_DIR / "cve_to_msf.yaml"
        try:
            with open(map_path) as f:
                return yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            return {}

    def find_modules_for_cves(
        self,
        cves: list[str],
        oos_attacks: list[str] | None = None,
    ) -> list[dict]:
        """Match CVEs to MSF modules, filtering out excluded modules."""
        mappings = self._load_mappings()
        oos = set(oos_attacks or [])
        matches = []
        for cve in cves:
            info = mappings.get(cve)
            if info and info["module"] not in oos:
                matches.append({"cve": cve, **info})
        return matches

    def _get_msf_client(self):
        """Create and return an MsfRpcClient connection."""
        from pymetasploit3.msfrpc import MsfRpcClient

        return MsfRpcClient(
            MSFRPC_PASS, server=MSFRPC_HOST, port=MSFRPC_PORT, ssl=False,
        )

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        **kwargs,
    ) -> dict:
        log = logger.bind(target_id=target_id)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping msf_check -- within cooldown")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        stats = {"found": 0, "in_scope": 0, "new": 0}
        oos_attacks = kwargs.get("oos_attacks", [])

        # Get CVEs already found by NmapTool
        async with get_session() as session:
            stmt = select(Vulnerability).where(
                Vulnerability.target_id == target_id,
                Vulnerability.source_tool == "nmap",
                Vulnerability.title.ilike("%CVE-%"),
            )
            result = await session.execute(stmt)
            nmap_vulns = list(result.scalars().all())

        if not nmap_vulns:
            log.info("No CVEs from nmap to verify")
            return stats

        # Extract CVE IDs from vulnerability titles
        cve_to_asset: dict[str, int | None] = {}
        for vuln in nmap_vulns:
            for cve in _CVE_RE.findall(vuln.title):
                cve_to_asset[cve] = vuln.asset_id

        modules = self.find_modules_for_cves(
            list(cve_to_asset.keys()), oos_attacks=oos_attacks,
        )
        if not modules:
            log.info("No matching MSF modules for discovered CVEs")
            return stats

        # Connect to msfrpcd
        try:
            client = self._get_msf_client()
        except Exception as exc:
            log.error(f"Failed to connect to msfrpcd: {exc}")
            return stats

        for mod_info in modules:
            asset_id = cve_to_asset.get(mod_info["cve"])
            if not asset_id:
                continue

            host = await self._get_asset_ip(asset_id)
            if not host:
                continue

            module_path = mod_info["module"]
            ports = mod_info.get("ports", [])

            try:
                exploit = client.modules.use("exploit", module_path)
                exploit["RHOSTS"] = host
                if ports:
                    exploit["RPORT"] = ports[0]

                check_result = exploit.check()
                result_str = str(check_result) if check_result else ""

                if "vulnerable" in result_str.lower():
                    stats["found"] += 1
                    stats["in_scope"] += 1
                    stats["new"] += 1

                    await self._save_vulnerability(
                        target_id=target_id,
                        asset_id=asset_id,
                        severity="critical",
                        title=f"Exploitable — {mod_info['cve']}",
                        description=(
                            f"Metasploit check confirmed {host} is vulnerable "
                            f"to {mod_info['cve']} via {module_path}"
                        ),
                        poc=(
                            f"msf> use {module_path}\n"
                            f"msf> set RHOSTS {host}\n"
                            f"msf> check\n"
                            f"Result: {result_str[:500]}"
                        ),
                    )

            except Exception as exc:
                log.error(f"MSF check failed for {mod_info['cve']}: {exc}")
                continue

        await self.update_tool_state(target_id, container_name)
        log.info("msf_check complete", extra=stats)
        return stats
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_tools.py -v -k "msf_check"`
Expected: All PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/tools/msf_check_tool.py tests/test_network_worker_tools.py
git commit -m "feat(network-worker): add MsfCheckTool for safe exploit verification"
```

---

## Task 10: Tools `__init__.py` & Pipeline

**Files:**
- Modify: `workers/network_worker/tools/__init__.py`
- Create: `workers/network_worker/pipeline.py`
- Create: `tests/test_network_worker_pipeline.py`

**Step 1: Write the failing tests**

Create `tests/test_network_worker_pipeline.py`:

```python
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


from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.anyio
async def test_handle_message_missing_target_id():
    from workers.network_worker.main import handle_message

    await handle_message("msg-1", {})


@pytest.mark.anyio
async def test_handle_message_target_not_found():
    from workers.network_worker.main import handle_message

    with patch("workers.network_worker.main.get_session") as mock_gs:
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        mock_gs.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_gs.return_value.__aexit__ = AsyncMock(return_value=False)

        await handle_message("msg-2", {"target_id": 999})
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_network_worker_pipeline.py -v`
Expected: FAIL

**Step 3: Write the implementations**

Update `workers/network_worker/tools/__init__.py`:

```python
from workers.network_worker.tools.naabu_tool import NaabuTool
from workers.network_worker.tools.nmap_tool import NmapTool
from workers.network_worker.tools.banner_grab_tool import BannerGrabTool
from workers.network_worker.tools.medusa_tool import MedusaTool
from workers.network_worker.tools.ldap_injection_tool import LdapInjectionTool
from workers.network_worker.tools.msf_check_tool import MsfCheckTool

__all__ = [
    "NaabuTool",
    "NmapTool",
    "BannerGrabTool",
    "MedusaTool",
    "LdapInjectionTool",
    "MsfCheckTool",
]
```

Create `workers/network_worker/pipeline.py`:

```python
# workers/network_worker/pipeline.py
"""Network testing pipeline: 4 sequential stages with checkpointing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.network_worker.base_tool import NetworkTestTool
from workers.network_worker.tools import (
    NaabuTool,
    NmapTool,
    BannerGrabTool,
    MedusaTool,
    LdapInjectionTool,
    MsfCheckTool,
)

logger = setup_logger("network-pipeline")


@dataclass
class Stage:
    name: str
    tool_classes: list[type[NetworkTestTool]]


STAGES: list[Stage] = [
    Stage("port_discovery", [NaabuTool]),
    Stage("service_scan", [NmapTool, BannerGrabTool]),
    Stage("credential_test", [MedusaTool, LdapInjectionTool]),
    Stage("exploit_verify", [MsfCheckTool]),
]

STAGE_INDEX: dict[str, int] = {}


def _rebuild_index() -> None:
    global STAGE_INDEX
    STAGE_INDEX = {stage.name: i for i, stage in enumerate(STAGES)}


_rebuild_index()


class Pipeline:
    """Orchestrates the 4-stage network testing pipeline with checkpointing."""

    def __init__(self, target_id: int, container_name: str) -> None:
        self.target_id = target_id
        self.container_name = container_name
        self.log = logger.bind(target_id=target_id)

    async def run(
        self,
        target,
        scope_manager: ScopeManager,
    ) -> None:
        """Execute the pipeline, resuming from last completed stage."""
        _rebuild_index()

        # Load oos_attacks once for the whole pipeline
        from workers.network_worker.tools.naabu_tool import NaabuTool

        loader = NaabuTool()
        oos_attacks = await loader._load_oos_attacks(self.target_id)

        completed_phase = await self._get_completed_phase()
        start_index = 0

        if completed_phase and completed_phase in STAGE_INDEX:
            start_index = STAGE_INDEX[completed_phase] + 1
            self.log.info(
                f"Resuming from stage {start_index}",
                extra={"completed_phase": completed_phase},
            )

        for stage in STAGES[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            stats = await self._run_stage(
                stage, target, scope_manager, oos_attacks=oos_attacks,
            )

            self.log.info(
                f"Stage complete: {stage.name}", extra={"stats": stats},
            )
            await push_task(f"events:{self.target_id}", {
                "event": "stage_complete",
                "stage": stage.name,
                "stats": stats,
            })

        await self._mark_completed()
        await push_task(f"events:{self.target_id}", {
            "event": "pipeline_complete",
            "target_id": self.target_id,
        })

    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        **kwargs,
    ) -> dict:
        """Run all tools in a stage concurrently."""
        tools = [cls() for cls in stage.tool_classes]

        tasks = [
            tool.execute(
                target=target,
                scope_manager=scope_manager,
                target_id=self.target_id,
                container_name=self.container_name,
                **kwargs,
            )
            for tool in tools
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._aggregate_results(stage.name, results)

    async def _get_completed_phase(self) -> str | None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
                JobState.status == "COMPLETED",
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            return job.current_phase if job else None

    async def _update_phase(self, phase: str) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.current_phase = phase
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    async def _mark_completed(self) -> None:
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == self.target_id,
                JobState.container_name == self.container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "COMPLETED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()

    @staticmethod
    def _merge_stats(aggregated: dict, result: dict) -> None:
        aggregated["found"] += result.get("found", 0)
        aggregated["in_scope"] += result.get("in_scope", 0)
        aggregated["new"] += result.get("new", 0)

    def _aggregate_results(self, stage_name: str, results: list) -> dict:
        aggregated = {"found": 0, "in_scope": 0, "new": 0}
        for r in results:
            if isinstance(r, Exception):
                self.log.error(
                    f"Tool failed in {stage_name}", extra={"error": str(r)}
                )
                continue
            self._merge_stats(aggregated, r)
        return aggregated
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_pipeline.py -v`
Expected: All PASSED

**Step 5: Commit**

```bash
git add workers/network_worker/tools/__init__.py workers/network_worker/pipeline.py tests/test_network_worker_pipeline.py
git commit -m "feat(network-worker): add 4-stage pipeline with checkpointing"
```

---

## Task 11: Main Entry Point

**Files:**
- Create: `workers/network_worker/main.py`

**Step 1: Run the handle_message tests to verify they fail**

Run: `pytest tests/test_network_worker_pipeline.py -v -k "handle_message"`
Expected: FAIL (main.py does not exist yet)

**Step 2: Write the implementation**

Create `workers/network_worker/main.py`:

```python
# workers/network_worker/main.py
"""Network testing worker entry point.

Listens on ``network_queue`` and runs the 4-stage
network testing pipeline for each incoming target.
Manages msfrpcd lifecycle on startup.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from sqlalchemy import select

from lib_webbh import (
    JobState,
    Target,
    get_session,
    listen_queue,
    setup_logger,
)
from lib_webbh.scope import ScopeManager

from workers.network_worker.pipeline import Pipeline

logger = setup_logger("network-worker")

HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
MSFRPC_PASS = os.environ.get("MSFRPC_PASS", "msf_internal")
MSFRPC_PORT = int(os.environ.get("MSFRPC_PORT", "55553"))


def get_container_name() -> str:
    return os.environ.get("HOSTNAME", "network-worker-unknown")


async def _start_msfrpcd() -> asyncio.subprocess.Process | None:
    """Start msfrpcd as a background subprocess."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "msfrpcd",
            "-P", MSFRPC_PASS,
            "-p", str(MSFRPC_PORT),
            "-S",  # no SSL
            "-f",  # foreground (we manage lifecycle)
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"msfrpcd started on port {MSFRPC_PORT}")
        return proc
    except FileNotFoundError:
        logger.warning("msfrpcd not found — MSF checks will be unavailable")
        return None


async def _wait_for_msfrpcd(
    max_retries: int = 30, delay: float = 2.0,
) -> bool:
    """Wait for msfrpcd to accept connections."""
    for attempt in range(max_retries):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient

            MsfRpcClient(
                MSFRPC_PASS, server="127.0.0.1", port=MSFRPC_PORT, ssl=False,
            )
            logger.info("msfrpcd is ready")
            return True
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(delay)
    logger.error("msfrpcd failed to start within timeout")
    return False


async def handle_message(msg_id: str, data: dict) -> None:
    """Process a single network_queue message."""
    target_id = data.get("target_id")

    if not target_id:
        logger.error("Message missing target_id", extra={"msg_id": msg_id})
        return

    log = logger.bind(target_id=target_id)
    log.info("Received network testing task", extra={"msg_id": msg_id})

    # Load target
    async with get_session() as session:
        stmt = select(Target).where(Target.id == target_id)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

    if target is None:
        log.error(f"Target {target_id} not found in database")
        return

    container_name = get_container_name()
    profile = target.target_profile or {}
    scope_manager = ScopeManager(profile)

    # Ensure job_state row
    async with get_session() as session:
        stmt = select(JobState).where(
            JobState.target_id == target_id,
            JobState.container_name == container_name,
        )
        result = await session.execute(stmt)
        job = result.scalar_one_or_none()

        if job is None:
            job = JobState(
                target_id=target_id,
                container_name=container_name,
                current_phase="init",
                status="RUNNING",
                last_seen=datetime.now(timezone.utc),
            )
            session.add(job)
        else:
            job.status = "RUNNING"
            job.last_seen = datetime.now(timezone.utc)
        await session.commit()

    # Run pipeline with heartbeat
    pipeline = Pipeline(target_id=target_id, container_name=container_name)
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(target_id, container_name)
    )

    try:
        await pipeline.run(target, scope_manager)
    except Exception:
        log.exception("Pipeline failed")
        async with get_session() as session:
            stmt = select(JobState).where(
                JobState.target_id == target_id,
                JobState.container_name == container_name,
            )
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                job.status = "FAILED"
                job.last_seen = datetime.now(timezone.utc)
                await session.commit()
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


async def _heartbeat_loop(target_id: int, container_name: str) -> None:
    """Update job_state.last_seen every HEARTBEAT_INTERVAL seconds."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_seen = datetime.now(timezone.utc)
                    await session.commit()
        except Exception:
            pass


async def main() -> None:
    """Entry point: start msfrpcd, then listen on network_queue."""
    container_name = get_container_name()
    logger.info(
        "Network testing worker starting", extra={"container": container_name},
    )

    # Start msfrpcd daemon
    msf_proc = await _start_msfrpcd()
    if msf_proc:
        await _wait_for_msfrpcd()

    await listen_queue(
        queue="network_queue",
        group="network_group",
        consumer=container_name,
        callback=handle_message,
    )


if __name__ == "__main__":
    asyncio.run(main())
```

**Step 3: Run tests to verify they pass**

Run: `pytest tests/test_network_worker_pipeline.py -v`
Expected: All PASSED

**Step 4: Commit**

```bash
git add workers/network_worker/main.py
git commit -m "feat(network-worker): add main.py entry point with msfrpcd lifecycle"
```

---

## Task 12: Dockerfile & docker-compose

**Files:**
- Create: `docker/Dockerfile.network`
- Modify: `docker-compose.yml`

**Step 1: Create the Dockerfile**

Create `docker/Dockerfile.network`:

```dockerfile
# docker/Dockerfile.network
# -------------------------------------------------------
# Network Testing Worker — Kali Linux with MSF + Nmap
# -------------------------------------------------------

FROM kalilinux/kali-rolling AS base

ENV DEBIAN_FRONTEND=noninteractive

# System tools + network testing suite
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    metasploit-framework \
    medusa \
    socat \
    ldap-utils \
    python3 \
    python3-pip \
    python3-dev \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install naabu binary
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSfL \
    "https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_linux_${ARCH}.zip" \
    -o /tmp/naabu.zip && \
    unzip /tmp/naabu.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/naabu && \
    rm /tmp/naabu.zip

# Python dependencies
RUN pip install --no-cache-dir --break-system-packages \
    pymetasploit3 \
    pyyaml \
    httpx

# Copy shared lib and worker code
COPY shared/ /app/shared/
RUN pip install --break-system-packages -e /app/shared/lib_webbh

COPY workers/ /app/workers/

WORKDIR /app

ENTRYPOINT ["python3", "-m", "workers.network_worker.main"]
```

**Step 2: Add docker-compose entry**

Add the following service block to `docker-compose.yml` after the last worker entry:

```yaml
  # ---------------------------------------------------------------------------
  # Network Worker — port enum, service fingerprint, exploit verification
  # ---------------------------------------------------------------------------
  network-worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.network
    container_name: webbh-network-worker
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
    volumes:
      - ./shared:/app/shared
    networks:
      - webbh-net
```

**Step 3: Commit**

```bash
git add docker/Dockerfile.network docker-compose.yml
git commit -m "feat(network-worker): add Dockerfile.network and docker-compose entry"
```

---

## Task 13: Final Integration — Run All Tests

**Step 1: Run the full network worker test suite**

Run: `pytest tests/test_network_worker_tools.py tests/test_network_worker_pipeline.py -v`
Expected: All PASSED

**Step 2: Run the full project test suite**

Run: `pytest -v`
Expected: All existing tests pass + new network worker tests pass (expect 1 Redis failure as before)

**Step 3: Final commit if any fixes needed**

Only if tests required adjustments. Otherwise, no action needed.
