# WSTG-CONF-01 Network Infrastructure Configuration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the `config_mgmt` worker's `network_config` stage to achieve full WSTG-CONF-01 compliance across three pillars: server CVE detection (NVD API), admin interface discovery (nmap + HTTP probing), and default credential testing (Hydra).

**Architecture:** The current single-tool `network_config` stage is split into two sequential stages: `network_config` runs `NetworkConfigTester` (CVE detection) and `AdminInterfaceFinder` (port scan + HTTP admin path probing) concurrently; `network_config_cred_test` runs `DefaultCredentialTester` (Hydra) sequentially after, reading admin interface URLs that `AdminInterfaceFinder` wrote to the DB. All three coherence files (pipeline.py, playbooks.py, worker-stages.ts) are updated in one commit.

**Tech Stack:** Python 3.10, httpx, SQLAlchemy async, nmap (apt), hydra (apt), NVD REST API v2.0, pytest + pytest-asyncio, Docker/apt for binary deps.

---

## File Map

| File | Action |
|------|--------|
| `docker/Dockerfile.config_mgmt` | Add `nmap` + `hydra` to apt install |
| `workers/config_mgmt/tools/network_config_tester.py` | Refactor: remove CORS, add version extraction + NVD lookup |
| `workers/config_mgmt/tools/admin_interface_finder.py` | New: nmap scan + HTTP admin path probing |
| `workers/config_mgmt/tools/default_credential_tester.py` | New: Hydra wrapper with rate-limiting and UA rotation |
| `workers/config_mgmt/tools/__init__.py` | Add imports for two new tool classes |
| `workers/config_mgmt/concurrency.py` | Fix TOOL_WEIGHTS — replace mismatched PascalCase names with actual `name` attr values |
| `workers/config_mgmt/pipeline.py` | Add `network_config_cred_test` stage, import new tools |
| `shared/lib_webbh/playbooks.py` | Add `network_config_cred_test` to `config_mgmt` stage list |
| `dashboard/src/lib/worker-stages.ts` | Add credential testing stage entry for config_mgmt |
| `tests/unit/config_mgmt/__init__.py` | New: empty init for test package |
| `tests/unit/config_mgmt/test_network_config_tester.py` | Unit tests: parse_output, build_command, no CORS |
| `tests/unit/config_mgmt/test_admin_interface_finder.py` | Unit tests: nmap parse, HTTP probe parse, build_command |
| `tests/unit/config_mgmt/test_default_credential_tester.py` | Unit tests: profile selection, Hydra command building, output parsing |
| `tests/e2e/test_config_mgmt.py` | Update: add new stage to assertions + timeouts |

---

## Task 1: Add nmap and hydra to Dockerfile.config_mgmt

**Files:**
- Modify: `docker/Dockerfile.config_mgmt`

- [ ] **Step 1: Add apt packages to the runtime layer**

Replace the existing apt-get block in `docker/Dockerfile.config_mgmt`:

```dockerfile
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    nmap \
    hydra && \
    rm -rf /var/lib/apt/lists/*
```

- [ ] **Step 2: Verify the Dockerfile builds**

```bash
docker build -f docker/Dockerfile.config_mgmt -t config-mgmt-test . --no-cache
```

Expected: build succeeds with no errors. `nmap` and `hydra` binaries present.

- [ ] **Step 3: Verify binaries exist in the image**

```bash
docker run --rm config-mgmt-test which nmap hydra
```

Expected output:
```
/usr/bin/nmap
/usr/bin/hydra
```

- [ ] **Step 4: Commit**

```bash
git add docker/Dockerfile.config_mgmt
git commit -m "feat(config-mgmt): add nmap and hydra to Dockerfile"
```

---

## Task 2: Write failing unit tests for refactored NetworkConfigTester

**Files:**
- Create: `tests/unit/config_mgmt/__init__.py`
- Create: `tests/unit/config_mgmt/test_network_config_tester.py`

- [ ] **Step 1: Create the test package**

```bash
New-Item -ItemType File tests/unit/config_mgmt/__init__.py
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/config_mgmt/test_network_config_tester.py`:

```python
"""Unit tests for refactored NetworkConfigTester (WSTG-CONF-01 pillar 1)."""
import json
import pytest

from workers.config_mgmt.tools.network_config_tester import NetworkConfigTester


def test_parse_output_server_banner_observation():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "observation": {
            "type": "server_banner",
            "value": "Apache/2.4.49",
            "details": {"header": "server", "product": "apache", "version": "2.4.49"},
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "server_banner"
    assert results[0]["observation"]["details"]["product"] == "apache"
    assert results[0]["observation"]["details"]["version"] == "2.4.49"


def test_parse_output_high_cvss_yields_vulnerability():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "vulnerability": {
            "name": "CVE-2021-41773: apache 2.4.49",
            "severity": "critical",
            "description": "Path traversal in Apache 2.4.49",
            "location": "https://example.com",
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["vulnerability"]["severity"] == "critical"
    assert "CVE-2021-41773" in results[0]["vulnerability"]["name"]


def test_parse_output_low_cvss_yields_server_cve_low_observation():
    tool = NetworkConfigTester()
    raw = json.dumps([{
        "observation": {
            "type": "server_cve_low",
            "value": "CVE-2021-12345",
            "details": {
                "product": "apache", "version": "2.4.49",
                "base_score": 5.3, "description": "Low risk issue",
            },
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "server_cve_low"
    assert results[0]["observation"]["details"]["base_score"] == 5.3


def test_parse_output_empty_stdout_returns_empty_list():
    tool = NetworkConfigTester()
    assert tool.parse_output("") == []


def test_parse_output_invalid_json_returns_empty_list():
    tool = NetworkConfigTester()
    assert tool.parse_output("not json at all") == []


def test_build_command_returns_python3_subprocess():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    assert isinstance(cmd[2], str)


def test_build_command_script_contains_nvd_api_call():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert "nvd.nist.gov" in cmd[2]


def test_build_command_script_contains_server_banner_emission():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert "server_banner" in cmd[2]


def test_build_command_script_has_no_cors_logic():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert "access-control-allow-origin" not in cmd[2].lower()
    assert "cors" not in cmd[2].lower()
    assert "evil.com" not in cmd[2]


def test_build_command_script_uses_version_headers():
    tool = NetworkConfigTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    script = cmd[2]
    assert "x-powered-by" in script.lower()
    assert "x-aspnet-version" in script.lower()
```

- [ ] **Step 3: Run tests and confirm they fail**

```bash
pytest tests/unit/config_mgmt/test_network_config_tester.py -v
```

Expected: several FAIL (parse_output returns wrong results with old code) or PASS if parse_output already parses JSON correctly. `test_build_command_script_has_no_cors_logic` should FAIL since current code has CORS logic.

---

## Task 3: Refactor NetworkConfigTester

**Files:**
- Modify: `workers/config_mgmt/tools/network_config_tester.py`

- [ ] **Step 1: Replace the file with the refactored implementation**

```python
"""Network configuration testing: server version detection and CVE lookup (WSTG-CONF-01)."""

from workers.config_mgmt.base_tool import ConfigMgmtTool


class NetworkConfigTester(ConfigMgmtTool):
    """Extract server version strings from HTTP headers and cross-reference NVD CVE database."""

    name = "network_config_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"

        script = f"""
import httpx, json, re, sys

results = []
base_url = {json.dumps(base_url)}

VERSION_HEADERS = [
    "server", "x-powered-by", "x-generator",
    "x-aspnet-version", "x-runtime", "x-served-by",
]

def extract_product_version(value):
    m = re.match(r'^([A-Za-z][\\w.-]*)[\\/]?(\\d[\\d.]+)?', value.strip())
    if m:
        product = m.group(1).lower()
        version = m.group(2) or ""
        return product, version
    return None, None

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    try:
        resp = client.head(base_url)
        if resp.status_code >= 400:
            resp = client.get(base_url)
    except Exception:
        resp = client.get(base_url)

    detected = []
    for h in VERSION_HEADERS:
        value = resp.headers.get(h, "")
        if not value:
            continue
        product, version = extract_product_version(value)
        if not product:
            continue
        detected.append({{"header": h, "raw_value": value, "product": product, "version": version}})
        results.append({{"observation": {{
            "type": "server_banner",
            "value": value,
            "details": {{"header": h, "product": product, "version": version}},
        }}}})
    client.close()

    nvd = httpx.Client(timeout=15)
    for item in detected:
        if not item["version"]:
            continue
        keyword = item["product"] + " " + item["version"]
        try:
            r = nvd.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={{"keywordSearch": keyword, "resultsPerPage": 10}},
                headers={{"Accept": "application/json"}},
            )
            if r.status_code != 200:
                continue
            data = r.json()
            for cve_item in data.get("vulnerabilities", []):
                cve = cve_item.get("cve", {{}})
                cve_id = cve.get("id", "")
                metrics = cve.get("metrics", {{}})
                base_score = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        base_score = entries[0].get("cvssData", {{}}).get("baseScore")
                        break
                if base_score is None:
                    continue
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                if base_score >= 7.0:
                    severity = "critical" if base_score >= 9.0 else "high"
                    results.append({{"vulnerability": {{
                        "name": f"{{cve_id}}: {{item['product']}} {{item['version']}}",
                        "severity": severity,
                        "description": desc,
                        "location": base_url,
                    }}}})
                else:
                    results.append({{"observation": {{
                        "type": "server_cve_low",
                        "value": cve_id,
                        "details": {{
                            "product": item["product"], "version": item["version"],
                            "base_score": base_score, "description": desc,
                        }},
                    }}}})
        except Exception:
            pass
    nvd.close()

except Exception as e:
    results.append({{"observation": {{"type": "test_error", "value": str(e), "details": {{"error": str(e)}}}}}})

print(json.dumps(results))
"""
        import json
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        import json as _json
        try:
            return _json.loads(stdout.strip())
        except (ValueError, _json.JSONDecodeError):
            return []
```

- [ ] **Step 2: Run the tests and verify they pass**

```bash
pytest tests/unit/config_mgmt/test_network_config_tester.py -v
```

Expected: all 9 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add workers/config_mgmt/tools/network_config_tester.py tests/unit/config_mgmt/
git commit -m "feat(config-mgmt): refactor NetworkConfigTester for server CVE detection (WSTG-CONF-01)"
```

---

## Task 4: Write failing unit tests for AdminInterfaceFinder

**Files:**
- Create: `tests/unit/config_mgmt/test_admin_interface_finder.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Unit tests for AdminInterfaceFinder (WSTG-CONF-01 pillar 2)."""
import json
import pytest

from workers.config_mgmt.tools.admin_interface_finder import AdminInterfaceFinder


NMAP_GREPPABLE_SAMPLE = (
    "Host: 10.0.0.1 (example.com)\tPorts: "
    "21/open/tcp//ftp//ProFTPD 1.3.5e/, "
    "80/open/tcp//http//Apache httpd 2.4.41/, "
    "445/open/tcp//microsoft-ds//Samba smbd 4.11.6/, "
    "8080/open/tcp//http//Apache Tomcat 9.0.37/\t"
    "Ignored State: closed (65531)\n"
)

NMAP_EMPTY_SAMPLE = (
    "Host: 10.0.0.1 ()\tPorts: \tIgnored State: closed (65535)\n"
)

NMAP_NO_HOST_LINE = "# Nmap scan report\n# Done.\n"


def test_parse_nmap_extracts_open_service_observations():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_GREPPABLE_SAMPLE)
    types = [r["observation"]["type"] for r in results]
    assert all(t == "open_service" for t in types)
    ports = [r["observation"]["details"]["port"] for r in results]
    assert 21 in ports
    assert 80 in ports
    assert 445 in ports
    assert 8080 in ports


def test_parse_nmap_flags_known_admin_ports():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_GREPPABLE_SAMPLE)
    by_port = {r["observation"]["details"]["port"]: r["observation"]["details"] for r in results}
    assert by_port[21]["is_admin_service"] is True    # FTP
    assert by_port[445]["is_admin_service"] is True   # SMB
    assert by_port[8080]["is_admin_service"] is True  # Alt HTTP
    assert by_port[80]["is_admin_service"] is False   # plain HTTP is not admin


def test_parse_nmap_empty_ports_returns_empty_list():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_EMPTY_SAMPLE)
    assert results == []


def test_parse_nmap_no_host_line_returns_empty_list():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_NO_HOST_LINE)
    assert results == []


def test_parse_nmap_captures_service_and_banner():
    tool = AdminInterfaceFinder()
    results = tool._parse_nmap_output(NMAP_GREPPABLE_SAMPLE)
    ftp_entry = next(r for r in results if r["observation"]["details"]["port"] == 21)
    assert ftp_entry["observation"]["details"]["service"] == "ftp"
    assert "ProFTPD" in ftp_entry["observation"]["details"]["banner"]


def test_parse_output_200_yields_admin_interface():
    tool = AdminInterfaceFinder()
    raw = json.dumps([{
        "observation": {
            "type": "admin_interface",
            "value": "https://example.com/admin",
            "details": {"path": "/admin", "status": 200, "content_length": 1234, "server": "Apache"},
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "admin_interface"
    assert results[0]["observation"]["value"] == "https://example.com/admin"


def test_parse_output_redirect_yields_admin_redirect():
    tool = AdminInterfaceFinder()
    raw = json.dumps([{
        "observation": {
            "type": "admin_redirect",
            "value": "https://example.com/wp-admin",
            "details": {"path": "/wp-admin", "status": 302, "redirect_to": "/wp-login.php"},
        }
    }])
    results = tool.parse_output(raw)
    assert len(results) == 1
    assert results[0]["observation"]["type"] == "admin_redirect"


def test_parse_output_invalid_json_returns_empty_list():
    tool = AdminInterfaceFinder()
    assert tool.parse_output("garbage") == []


def test_build_command_returns_nmap_with_full_port_range():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert cmd[0] == "nmap"
    assert "-p-" in cmd
    assert "-sV" in cmd
    assert "--open" in cmd
    assert "-oG" in cmd
    assert "example.com" in cmd


def test_build_command_with_url_extracts_hostname():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "https://example.com/path"})()
    cmd = tool.build_command(target)
    assert "example.com" in cmd
    assert "https://" not in " ".join(cmd)


def test_build_http_probe_command_contains_admin_paths():
    tool = AdminInterfaceFinder()
    cmd = tool._build_http_probe_command("https://example.com")
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    script = cmd[2]
    assert "/wp-admin" in script
    assert "/manager/html" in script
    assert "/actuator" in script
    assert "/.git/HEAD" in script


def test_extract_host_from_url():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "https://sub.example.com:8443/path"})()
    assert tool._extract_host(target) == "sub.example.com"


def test_extract_host_from_plain_domain():
    tool = AdminInterfaceFinder()
    target = type("T", (), {"target_value": "example.com"})()
    assert tool._extract_host(target) == "example.com"
```

- [ ] **Step 2: Run and confirm they fail (file doesn't exist yet)**

```bash
pytest tests/unit/config_mgmt/test_admin_interface_finder.py -v
```

Expected: `ModuleNotFoundError` for `admin_interface_finder`.

---

## Task 5: Implement AdminInterfaceFinder

**Files:**
- Create: `workers/config_mgmt/tools/admin_interface_finder.py`

- [ ] **Step 1: Create the implementation**

```python
"""Admin interface and infrastructure discovery (WSTG-CONF-01 pillar 2)."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from lib_webbh import JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager
from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-tool")

ADMIN_PORTS = {21, 161, 445, 623, 2049, 6379, 8080, 8443, 8888, 9200, 9300, 27017, 5432, 3306, 1433}

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin/login", "/manage", "/manager",
    "/console", "/server-status", "/nginx_status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env",
    "/manager/html", "/host-manager/html",
    "/wp-admin", "/wp-login.php", "/administrator/index.php", "/admin.php",
    "/phpmyadmin", "/pma", "/cpanel", "/webmin", "/kibana", "/solr",
    "/jenkins", "/grafana",
    "/.env", "/config.php", "/web.config", "/.git/HEAD",
]


class AdminInterfaceFinder(ConfigMgmtTool):
    """Discover admin interfaces via nmap port scan and HTTP path probing."""

    name = "admin_interface_finder"

    def _extract_host(self, target) -> str:
        value = getattr(target, "target_value", str(target))
        if "://" in value:
            return urlparse(value).hostname or value
        return value.split(":")[0]

    def _extract_base_url(self, target) -> str:
        value = getattr(target, "target_value", str(target))
        if value.startswith(("http://", "https://")):
            return value
        return f"https://{value}"

    def build_command(self, target, headers=None) -> list[str]:
        host = self._extract_host(target)
        return ["nmap", "-p-", "-sV", "--open", "-oG", "-", host]

    def _parse_nmap_output(self, stdout: str) -> list:
        results = []
        port_re = re.compile(r"(\d+)/(open)/(tcp|udp)//([^/]*)//([^/]*)")
        for line in stdout.splitlines():
            if not line.startswith("Host:"):
                continue
            for m in port_re.finditer(line):
                port = int(m.group(1))
                proto = m.group(3)
                service = m.group(4).strip()
                banner = m.group(5).strip()
                results.append({"observation": {
                    "type": "open_service",
                    "value": f"{port}/{proto}",
                    "details": {
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "banner": banner,
                        "is_admin_service": port in ADMIN_PORTS,
                    },
                }})
        return results

    def _build_http_probe_command(self, base_url: str) -> list[str]:
        paths_json = json.dumps(ADMIN_PATHS)
        script = f"""
import httpx, json
results = []
base_url = {json.dumps(base_url)}
paths = {paths_json}
try:
    client = httpx.Client(follow_redirects=False, timeout=8, verify=False)
    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                results.append({{"observation": {{"type": "admin_interface", "value": url, "details": {{"path": path, "status": 200, "content_length": len(resp.content), "server": resp.headers.get("server", "")}}}}}})
            elif resp.status_code in (301, 302, 307, 308):
                results.append({{"observation": {{"type": "admin_redirect", "value": url, "details": {{"path": path, "status": resp.status_code, "redirect_to": resp.headers.get("location", "")}}}}}})
        except Exception:
            pass
    client.close()
except Exception as e:
    results.append({{"observation": {{"type": "test_error", "value": str(e), "details": {{"error": str(e)}}}}}})
print(json.dumps(results))
"""
        return ["python3", "-c", script]

    def parse_output(self, stdout: str) -> list:
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, asset_type="job")

        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0, "message": f"{self.name} started",
            })

            all_results = []

            # Phase A: nmap full-range port scan
            try:
                nmap_stdout = await self.run_subprocess(self.build_command(target, headers))
                all_results.extend(self._parse_nmap_output(nmap_stdout))
            except (asyncio.TimeoutError, FileNotFoundError) as exc:
                log.warning(f"{self.name}: nmap phase failed — {exc}")

            # Phase B: HTTP admin path probing
            try:
                http_stdout = await self.run_subprocess(
                    self._build_http_probe_command(self._extract_base_url(target))
                )
                all_results.extend(self.parse_output(http_stdout))
            except asyncio.TimeoutError:
                log.warning(f"{self.name}: HTTP probe timed out")

            found = len(all_results)
            new_count = 0
            in_scope_count = 0
            for item in all_results:
                inserted = await self._process_result(item, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    from datetime import datetime as _dt
                    job.last_tool_executed = self.name
                    job.last_seen = _dt.utcnow()
                    await session.commit()

            stats = {"found": found, "in_scope": in_scope_count, "new": new_count, "skipped_cooldown": False}

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": f"{self.name}: {new_count} new, {in_scope_count} in scope, {found} total",
            })

            log.info(f"{self.name} complete", extra={"tool": self.name, **stats})
            return stats

        finally:
            sem.release()
```

- [ ] **Step 2: Run the tests and verify they pass**

```bash
pytest tests/unit/config_mgmt/test_admin_interface_finder.py -v
```

Expected: all 13 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add workers/config_mgmt/tools/admin_interface_finder.py tests/unit/config_mgmt/test_admin_interface_finder.py
git commit -m "feat(config-mgmt): add AdminInterfaceFinder for nmap + HTTP admin path probing (WSTG-CONF-01)"
```

---

## Task 6: Write failing unit tests for DefaultCredentialTester

**Files:**
- Create: `tests/unit/config_mgmt/test_default_credential_tester.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Unit tests for DefaultCredentialTester (WSTG-CONF-01 pillar 3)."""
import pytest

from workers.config_mgmt.tools.default_credential_tester import DefaultCredentialTester


HYDRA_SUCCESS_OUTPUT = (
    "[DATA] attacking http-form-post://example.com:80/wp-login.php\n"
    "[80][http-form-post] host: example.com   login: admin   password: admin\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
)

HYDRA_FAILURE_OUTPUT = (
    "[DATA] attacking http-form-post://example.com:80/admin\n"
    "[DATA] max 1 task per 1 server, overall 1 task, 6 login tries (l:2/p:3)\n"
    "1 of 1 target completed, 0 valid passwords found\n"
)

HYDRA_EMPTY_OUTPUT = ""


def test_parse_hydra_success_yields_critical_vulnerability():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_SUCCESS_OUTPUT, "https://example.com/wp-login.php")
    vulns = [r for r in results if "vulnerability" in r]
    assert len(vulns) == 1
    assert vulns[0]["vulnerability"]["severity"] == "critical"
    assert "admin" in vulns[0]["vulnerability"]["description"]


def test_parse_hydra_success_includes_credential_test_result_observation():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_SUCCESS_OUTPUT, "https://example.com/wp-login.php")
    obs = [r for r in results if "observation" in r]
    assert len(obs) == 1
    assert obs[0]["observation"]["type"] == "credential_test_result"
    assert obs[0]["observation"]["details"]["outcome"] == "credentials_found"
    assert obs[0]["observation"]["details"]["credentials_found"] == 1


def test_parse_hydra_failure_yields_no_vulnerability():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_FAILURE_OUTPUT, "https://example.com/admin")
    vulns = [r for r in results if "vulnerability" in r]
    assert len(vulns) == 0


def test_parse_hydra_failure_yields_no_credentials_found_observation():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_FAILURE_OUTPUT, "https://example.com/admin")
    obs = [r for r in results if "observation" in r]
    assert len(obs) == 1
    assert obs[0]["observation"]["details"]["outcome"] == "no_credentials_found"
    assert obs[0]["observation"]["details"]["credentials_found"] == 0


def test_parse_hydra_empty_output_yields_only_observation():
    tool = DefaultCredentialTester()
    results = tool._parse_hydra_output(HYDRA_EMPTY_OUTPUT, "https://example.com/admin")
    assert len(results) == 1
    assert "observation" in results[0]


def test_get_profile_wordpress_path():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/wp-admin")
    assert "admin" in profile["users"]
    assert "is wrong" in profile["failure_string"]
    assert profile["module"] == "http-form-post"


def test_get_profile_wordpress_login_path():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/wp-login.php")
    assert "admin" in profile["users"]


def test_get_profile_tomcat():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/manager/html")
    assert "tomcat" in profile["users"]
    assert "s3cret" in profile["passwords"]


def test_get_profile_jenkins():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/jenkins")
    assert "admin" in profile["users"]


def test_get_profile_unknown_path_returns_generic():
    tool = DefaultCredentialTester()
    profile = tool._get_profile("/some-unknown-panel")
    assert "admin" in profile["users"]
    assert "admin" in profile["passwords"]
    assert profile["module"] == "http-form-post"


def test_build_hydra_command_single_thread():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=80, path="/admin",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=3, ua="Mozilla/5.0", failure_string="invalid", module="http-form-post",
    )
    assert cmd[0] == "hydra"
    assert "-t" in cmd
    t_index = cmd.index("-t")
    assert cmd[t_index + 1] == "1"


def test_build_hydra_command_has_wait_flag():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=80, path="/admin",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=5, ua="Firefox/125.0", failure_string="failed", module="http-form-post",
    )
    assert "-w" in cmd
    w_index = cmd.index("-w")
    assert cmd[w_index + 1] == "5"


def test_build_hydra_command_embeds_ua_in_module_string():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=80, path="/admin",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=3, ua="Chrome/124.0", failure_string="invalid", module="http-form-post",
    )
    cmd_str = " ".join(cmd)
    assert "Chrome/124.0" in cmd_str


def test_build_hydra_command_http_get_module_uses_path_only():
    tool = DefaultCredentialTester()
    cmd = tool._build_hydra_command(
        host="example.com", port=8983, path="/solr",
        userlist_path="/tmp/u.txt", passlist_path="/tmp/p.txt",
        jitter=3, ua="Mozilla/5.0", failure_string="Unauthorized", module="http-get",
    )
    # For http-get, the module string should just be the path
    assert "http-get" in cmd
    idx = cmd.index("http-get")
    assert cmd[idx + 1] == "/solr"
    assert "^USER^" not in " ".join(cmd)


def test_build_command_returns_true_placeholder():
    tool = DefaultCredentialTester()
    target = type("T", (), {"target_value": "example.com"})()
    cmd = tool.build_command(target)
    assert cmd == ["true"]
```

- [ ] **Step 2: Run and confirm they fail**

```bash
pytest tests/unit/config_mgmt/test_default_credential_tester.py -v
```

Expected: `ModuleNotFoundError` for `default_credential_tester`.

---

## Task 7: Implement DefaultCredentialTester

**Files:**
- Create: `workers/config_mgmt/tools/default_credential_tester.py`

- [ ] **Step 1: Create the implementation**

```python
"""Default credential testing via Hydra (WSTG-CONF-01 pillar 3)."""

from __future__ import annotations

import asyncio
import os
import random
import re
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from lib_webbh import JobState, Observation, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager
from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-tool")

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_PROFILES: dict[str, dict] = {
    "wordpress": {
        "paths": ["/wp-admin", "/wp-login.php"],
        "users": ["admin", "administrator"],
        "passwords": ["admin", "password", "wordpress", "123456"],
        "module": "http-form-post",
        "failure_string": "is wrong",
    },
    "tomcat": {
        "paths": ["/manager/html", "/host-manager/html"],
        "users": ["tomcat", "admin", "manager"],
        "passwords": ["tomcat", "s3cret", "manager", "admin"],
        "module": "http-form-post",
        "failure_string": "Invalid credentials",
    },
    "solr": {
        "paths": ["/solr"],
        "users": ["solr"],
        "passwords": ["SolrRocks", "admin", "solr"],
        "module": "http-get",
        "failure_string": "Unauthorized",
    },
    "jenkins": {
        "paths": ["/jenkins"],
        "users": ["admin", "jenkins"],
        "passwords": ["admin", "jenkins", "password"],
        "module": "http-form-post",
        "failure_string": "Invalid username or password",
    },
    "kibana": {
        "paths": ["/kibana"],
        "users": ["elastic", "kibana"],
        "passwords": ["changeme", "elastic"],
        "module": "http-form-post",
        "failure_string": "Invalid username or password",
    },
    "generic": {
        "paths": [],
        "users": ["admin", "root", "administrator"],
        "passwords": ["admin", "password", "123456", "root", "admin123"],
        "module": "http-form-post",
        "failure_string": "invalid",
    },
}

_SUCCESS_RE = re.compile(r"\[\d+\]\[[\w-]+\] host: \S+\s+login: (\S+)\s+password: (\S+)")


class DefaultCredentialTester(ConfigMgmtTool):
    """Test default credentials on admin interfaces discovered by AdminInterfaceFinder."""

    name = "default_credential_tester"
    _USER_AGENTS = _USER_AGENTS

    def build_command(self, target, headers=None) -> list[str]:
        # Satisfies the abstract contract; execute() is fully overridden.
        return ["true"]

    def parse_output(self, stdout: str) -> list:
        # Satisfies the abstract contract; execute() is fully overridden.
        return []

    def _get_profile(self, path: str) -> dict:
        for name, profile in _PROFILES.items():
            if name == "generic":
                continue
            if any(path.startswith(p) for p in profile["paths"]):
                return profile
        return _PROFILES["generic"]

    def _build_hydra_command(
        self,
        host: str,
        port: int,
        path: str,
        userlist_path: str,
        passlist_path: str,
        jitter: int,
        ua: str,
        failure_string: str,
        module: str,
    ) -> list[str]:
        if module == "http-get":
            module_str = path
        else:
            module_str = f"{path}:user=^USER^&pass=^PASS^:F={failure_string}:H=User-Agent: {ua}"
        return [
            "hydra",
            "-L", userlist_path,
            "-P", passlist_path,
            "-t", "1",
            "-w", str(jitter),
            "-s", str(port),
            host,
            module,
            module_str,
        ]

    def _parse_hydra_output(self, stdout: str, url: str) -> list:
        results = []
        successes = _SUCCESS_RE.findall(stdout)
        for login, password in successes:
            results.append({"vulnerability": {
                "name": f"Default credentials found at {url}",
                "severity": "critical",
                "description": f"Login succeeded with username '{login}' and password '{password}'",
                "location": url,
            }})
        outcome = "credentials_found" if successes else "no_credentials_found"
        results.append({"observation": {
            "type": "credential_test_result",
            "value": url,
            "details": {"url": url, "outcome": outcome, "credentials_found": len(successes)},
        }})
        return results

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, asset_type="job")

        if await self.check_cooldown(target_id, container_name):
            log.info(f"Skipping {self.name} — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0, "message": f"{self.name} started",
            })

            async with get_session() as session:
                stmt = select(Observation).where(
                    Observation.target_id == target_id,
                    Observation.observation_type == "admin_interface",
                    Observation.source_tool == "admin_interface_finder",
                )
                result = await session.execute(stmt)
                admin_interfaces = result.scalars().all()

            if not admin_interfaces:
                log.info(f"{self.name}: no admin interfaces to test, skipping")
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            cred_rate_limit = int(os.environ.get("CONF_CRED_RATE_LIMIT", "3"))
            all_results = []

            for obs in admin_interfaces:
                url = obs.value
                details = obs.details or {}
                path = details.get("path", "/admin")

                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)

                profile = self._get_profile(path)
                jitter = int(random.uniform(cred_rate_limit, cred_rate_limit * 2.5))
                ua = random.choice(self._USER_AGENTS)

                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
                    uf.write("\n".join(profile["users"]))
                    userlist_path = uf.name
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
                    pf.write("\n".join(profile["passwords"]))
                    passlist_path = pf.name

                try:
                    cmd = self._build_hydra_command(
                        host=host, port=port, path=path,
                        userlist_path=userlist_path, passlist_path=passlist_path,
                        jitter=jitter, ua=ua,
                        failure_string=profile["failure_string"],
                        module=profile["module"],
                    )
                    try:
                        stdout = await self.run_subprocess(cmd)
                        all_results.extend(self._parse_hydra_output(stdout, url))
                    except (asyncio.TimeoutError, FileNotFoundError) as exc:
                        log.warning(f"{self.name}: hydra failed for {url} — {exc}")
                finally:
                    for tmp in (userlist_path, passlist_path):
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass

            found = len(all_results)
            new_count = 0
            in_scope_count = 0
            for item in all_results:
                inserted = await self._process_result(item, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.utcnow()
                    await session.commit()

            stats = {"found": found, "in_scope": in_scope_count, "new": new_count, "skipped_cooldown": False}

            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": f"{self.name}: {new_count} new, {in_scope_count} in scope, {found} total",
            })

            log.info(f"{self.name} complete", extra={"tool": self.name, **stats})
            return stats

        finally:
            sem.release()
```

- [ ] **Step 2: Run the tests and verify they pass**

```bash
pytest tests/unit/config_mgmt/test_default_credential_tester.py -v
```

Expected: all 15 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add workers/config_mgmt/tools/default_credential_tester.py tests/unit/config_mgmt/test_default_credential_tester.py
git commit -m "feat(config-mgmt): add DefaultCredentialTester with Hydra rate-limiting and UA rotation (WSTG-CONF-01)"
```

---

## Task 8: Fix concurrency.py TOOL_WEIGHTS

**Files:**
- Modify: `workers/config_mgmt/concurrency.py`

The current `TOOL_WEIGHTS` uses PascalCase class names, but the `get_tool_weight()` lookup uses `self.name` (snake_case). Every tool was silently getting the `LIGHT` fallback. Fix by keying on actual `name` attribute values.

- [ ] **Step 1: Replace the TOOL_WEIGHTS dict**

In `workers/config_mgmt/concurrency.py`, replace the entire `TOOL_WEIGHTS` dict:

```python
TOOL_WEIGHTS = {
    "network_config_tester":      WeightClass.LIGHT,
    "admin_interface_finder":     WeightClass.HEAVY,
    "default_credential_tester":  WeightClass.HEAVY,
    "platform_fingerprinter":     WeightClass.LIGHT,
    "file_extension_tester":      WeightClass.LIGHT,
    "backup_file_finder":         WeightClass.LIGHT,
    "FfufTool":                   WeightClass.HEAVY,  # ffuf_tool.py uses "FfufTool" as name
    "api_discovery_tool":         WeightClass.LIGHT,
    "http_method_tester":         WeightClass.LIGHT,
    "hsts_tester":                WeightClass.LIGHT,
    "rpc_tester":                 WeightClass.LIGHT,
    "file_inclusion_tester":      WeightClass.LIGHT,
    "subdomain_takeover_checker": WeightClass.LIGHT,
    "cloud_storage_auditor":      WeightClass.LIGHT,
}
```

- [ ] **Step 2: Run all config_mgmt unit tests to confirm nothing regressed**

```bash
pytest tests/unit/config_mgmt/ -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add workers/config_mgmt/concurrency.py
git commit -m "fix(config-mgmt): align TOOL_WEIGHTS keys with actual tool name attributes"
```

---

## Task 9: Update tools/__init__.py

**Files:**
- Modify: `workers/config_mgmt/tools/__init__.py`

- [ ] **Step 1: Add imports for the two new tool classes**

Replace `workers/config_mgmt/tools/__init__.py` with:

```python
# Config management tools package

from .network_config_tester import NetworkConfigTester
from .admin_interface_finder import AdminInterfaceFinder
from .default_credential_tester import DefaultCredentialTester
from .platform_fingerprinter import PlatformFingerprinter
from .file_extension_tester import FileExtensionTester
from .backup_file_finder import BackupFileFinder
from .ffuf_tool import FfufTool
from .api_discovery_tool import ApiDiscoveryTool
from .http_method_tester import HttpMethodTester
from .hsts_tester import HstsTester
from .rpc_tester import RpcTester
from .file_inclusion_tester import FileInclusionTester
from .subdomain_takeover_checker import SubdomainTakeoverChecker
from .cloud_storage_auditor import CloudStorageAuditor

__all__ = [
    "NetworkConfigTester",
    "AdminInterfaceFinder",
    "DefaultCredentialTester",
    "PlatformFingerprinter",
    "FileExtensionTester",
    "BackupFileFinder",
    "FfufTool",
    "ApiDiscoveryTool",
    "HttpMethodTester",
    "HstsTester",
    "RpcTester",
    "FileInclusionTester",
    "SubdomainTakeoverChecker",
    "CloudStorageAuditor",
]
```

- [ ] **Step 2: Verify the import works**

```bash
python -c "from workers.config_mgmt.tools import AdminInterfaceFinder, DefaultCredentialTester; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add workers/config_mgmt/tools/__init__.py
git commit -m "chore(config-mgmt): export AdminInterfaceFinder and DefaultCredentialTester from tools package"
```

---

## Task 10: Three-layer sync — pipeline.py + playbooks.py + worker-stages.ts

**CLAUDE.md rule:** All three files must be updated in the same commit.

**Files:**
- Modify: `workers/config_mgmt/pipeline.py`
- Modify: `shared/lib_webbh/playbooks.py`
- Modify: `dashboard/src/lib/worker-stages.ts`

- [ ] **Step 1: Update pipeline.py**

In `workers/config_mgmt/pipeline.py`, update the imports block to add `AdminInterfaceFinder` and `DefaultCredentialTester`:

```python
from workers.config_mgmt.tools import (
    NetworkConfigTester,
    AdminInterfaceFinder,
    DefaultCredentialTester,
    PlatformFingerprinter,
    FileExtensionTester,
    BackupFileFinder,
    FfufTool,
    ApiDiscoveryTool,
    HttpMethodTester,
    HstsTester,
    RpcTester,
    FileInclusionTester,
    SubdomainTakeoverChecker,
    CloudStorageAuditor,
)
```

Update the `STAGES` list (replace only the first two entries):

```python
STAGES = [
    Stage("network_config",           [NetworkConfigTester, AdminInterfaceFinder]),
    Stage("network_config_cred_test", [DefaultCredentialTester]),
    Stage("platform_config",          [PlatformFingerprinter]),
    Stage("file_extension_handling",  [FileExtensionTester]),
    Stage("backup_files",             [BackupFileFinder, FfufTool]),
    Stage("api_discovery",            [ApiDiscoveryTool]),
    Stage("http_methods",             [HttpMethodTester]),
    Stage("hsts_testing",             [HstsTester]),
    Stage("rpc_testing",              [RpcTester]),
    Stage("file_inclusion",           [FileInclusionTester]),
    Stage("subdomain_takeover",       [SubdomainTakeoverChecker]),
    Stage("cloud_storage",            [CloudStorageAuditor]),
]
```

- [ ] **Step 2: Update playbooks.py**

In `shared/lib_webbh/playbooks.py`, find the `"config_mgmt"` key in `PIPELINE_STAGES` and add `"network_config_cred_test"` after `"network_config"`:

```python
"config_mgmt": [
    "network_config",
    "network_config_cred_test",
    "platform_config",
    "file_extension_handling",
    "backup_files",
    "api_discovery",
    "http_methods",
    "hsts_testing",
    "rpc_testing",
    "file_inclusion",
    "subdomain_takeover",
    "cloud_storage",
],
```

- [ ] **Step 3: Update worker-stages.ts**

In `dashboard/src/lib/worker-stages.ts`, update the `config_mgmt` array to insert the credential testing stage after Network Configuration:

```typescript
config_mgmt: [
  { id: "1",  name: "Network Configuration", stageName: "network_config",           sectionId: "WSTG-CONF-01" },
  { id: "1b", name: "Credential Testing",    stageName: "network_config_cred_test", sectionId: "WSTG-CONF-01" },
  { id: "2",  name: "Platform Configuration",         stageName: "platform_config",         sectionId: "WSTG-CONF-02" },
  { id: "3",  name: "File Extension Handling",         stageName: "file_extension_handling",  sectionId: "WSTG-CONF-03" },
  { id: "4",  name: "Backup Files",                    stageName: "backup_files",             sectionId: "WSTG-CONF-04" },
  { id: "5",  name: "API Discovery",                   stageName: "api_discovery",            sectionId: "WSTG-CONF-05" },
  { id: "6",  name: "HTTP Methods",                    stageName: "http_methods",             sectionId: "WSTG-CONF-06" },
  { id: "7",  name: "HTTP Strict Transport Security",  stageName: "hsts_testing",             sectionId: "WSTG-CONF-07" },
  { id: "8",  name: "RPC Testing",                     stageName: "rpc_testing",              sectionId: "WSTG-CONF-08" },
  { id: "9",  name: "File Inclusion",                  stageName: "file_inclusion",           sectionId: "WSTG-CONF-09" },
  { id: "10", name: "Subdomain Takeover",              stageName: "subdomain_takeover",       sectionId: "WSTG-CONF-10" },
  { id: "11", name: "Cloud Storage",                   stageName: "cloud_storage",            sectionId: "WSTG-CONF-11" },
],
```

- [ ] **Step 4: Verify pipeline.py imports parse cleanly**

```bash
python -c "from workers.config_mgmt.pipeline import STAGES; print([s.name for s in STAGES])"
```

Expected output:
```
['network_config', 'network_config_cred_test', 'platform_config', 'file_extension_handling', 'backup_files', 'api_discovery', 'http_methods', 'hsts_testing', 'rpc_testing', 'file_inclusion', 'subdomain_takeover', 'cloud_storage']
```

- [ ] **Step 5: Commit all three files together**

```bash
git add workers/config_mgmt/pipeline.py shared/lib_webbh/playbooks.py dashboard/src/lib/worker-stages.ts
git commit -m "feat(config-mgmt): add network_config_cred_test stage — three-layer sync (WSTG-CONF-01)"
```

---

## Task 11: Update e2e test for config_mgmt

**Files:**
- Modify: `tests/e2e/test_config_mgmt.py`

- [ ] **Step 1: Add the new stage to assertions and timeouts**

Replace `tests/e2e/test_config_mgmt.py` with:

```python
"""E2E tests for config_mgmt worker (WSTG-CONF-01 through CONF-11)."""
import pytest
from conftest import (
    assert_assets, assert_job_completed,
    cleanup_target, create_target,
)

pytestmark = pytest.mark.e2e

WORKER = "config_mgmt"
PLAYBOOK = "e2e_config_mgmt"
LAST_STAGE = "cloud_storage"

STAGE_ASSERTIONS = {
    "network_config":          lambda c, tid: assert_assets(c, tid),
    "network_config_cred_test": None,
    "platform_config":         lambda c, tid: assert_assets(c, tid),
    "file_extension_handling": lambda c, tid: assert_assets(c, tid),
    "backup_files":            None,
    "api_discovery":           lambda c, tid: assert_assets(c, tid),
    "http_methods":            lambda c, tid: assert_assets(c, tid),
    "hsts_testing":            None,
    "rpc_testing":             None,
    "file_inclusion":          None,
    "subdomain_takeover":      None,
    "cloud_storage":           None,
}

STAGE_TIMEOUTS = {
    "network_config":          600,  # nmap -p- can take several minutes
    "network_config_cred_test": 300,  # Hydra with rate-limiting
    "platform_config":         120,
    "file_extension_handling": 120,
    "backup_files":            120,
    "api_discovery":           180,
    "http_methods":            120,
    "hsts_testing":            120,
    "rpc_testing":             120,
    "file_inclusion":          120,
    "subdomain_takeover":      180,
    "cloud_storage":           180,
}


@pytest.fixture(scope="module")
async def pipeline_result(client, sse_monitor):
    target_id = await create_target(client, PLAYBOOK, "E2E-ConfigMgmt")
    try:
        report = await sse_monitor.run(target_id, WORKER, STAGE_ASSERTIONS, STAGE_TIMEOUTS)
        yield target_id, report
    finally:
        await cleanup_target(client, target_id)


async def test_config_mgmt_pipeline_stages(pipeline_result):
    _, report = pipeline_result
    assert report.errors == [], f"Pipeline emitted errors: {report.errors}"
    assert report.container_logs_clean, "config_mgmt container has ERROR/Traceback in logs"
    assert report.completed_stages == list(STAGE_ASSERTIONS.keys()), (
        f"Stage mismatch: got {report.completed_stages}"
    )


async def test_config_mgmt_job_state(client, pipeline_result):
    target_id, _ = pipeline_result
    await assert_job_completed(client, target_id, WORKER, LAST_STAGE)
```

- [ ] **Step 2: Run all unit tests to confirm nothing is broken**

```bash
pytest tests/unit/config_mgmt/ -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_config_mgmt.py
git commit -m "test(config-mgmt): add network_config_cred_test stage to e2e assertions"
```

---

## Self-Review

**Spec coverage check:**
- ✅ Pillar 1 (server CVE detection via NVD) — Task 2 + 3
- ✅ Pillar 2 (nmap full-range + HTTP admin paths) — Task 4 + 5
- ✅ Pillar 3 (Hydra default credential testing) — Task 6 + 7
- ✅ CORS removed from this stage — verified in test `test_build_command_script_has_no_cors_logic`
- ✅ Rate-limiting via `CONF_CRED_RATE_LIMIT` env var — Task 7 implementation
- ✅ UA rotation — Task 7 `_USER_AGENTS` pool
- ✅ Per-product Hydra wordlists — Task 7 `_PROFILES`
- ✅ Sequential stage dependency (AdminInterfaceFinder writes DB; DefaultCredentialTester reads it) — Task 10
- ✅ Dockerfile binaries — Task 1
- ✅ TOOL_WEIGHTS fix — Task 8
- ✅ Three-layer sync in one commit — Task 10
- ✅ e2e test updated — Task 11

**Type consistency:** `_parse_hydra_output(stdout: str, url: str)` called in Task 7 `execute()` with `(stdout, url)` — matches signature. `_build_hydra_command(host, port, path, userlist_path, passlist_path, jitter, ua, failure_string, module)` called in Task 7 `execute()` with all 9 named kwargs — matches. `_parse_nmap_output(stdout: str)` called in Task 5 `execute()` with `(nmap_stdout,)` — matches.

**Placeholder scan:** No TBDs, no "implement later" phrases found.
