# Info Gathering Stage 4 — Enumerate Applications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the `info_gathering` pipeline's Stage 4 from subdomain-only discovery to full WSTG-INFO-04 coverage by adding `CTLogSearcher`, `AppPathEnumerator`, moving `Naabu` from Stage 9, and renaming the stage to `enumerate_applications`.

**Architecture:** Two new tool classes follow the existing `InfoGatheringTool` pattern — `CTLogSearcher` makes a direct aiohttp call to crt.sh, `AppPathEnumerator` wraps ffuf via `run_subprocess`. The stage rename propagates across Python, TypeScript, JSON, and Playwright test files in one atomic commit to avoid broken intermediate states.

**Tech Stack:** Python asyncio, aiohttp, ffuf (CLI), pytest + anyio, TypeScript (dashboard constants), Playwright (e2e tests)

**Spec:** `docs/superpowers/specs/2026-05-14-info-gathering-stage4-design.md`

---

## File Map

**Create:**
- `workers/info_gathering/tools/ct_log_searcher.py` — CTLogSearcher tool (crt.sh HTTP API)
- `workers/info_gathering/tools/app_path_enumerator.py` — AppPathEnumerator tool (ffuf subprocess)
- `tests/test_ct_log_searcher.py` — unit tests for CTLogSearcher
- `tests/test_app_path_enumerator.py` — unit tests for AppPathEnumerator

**Modify:**
- `workers/info_gathering/pipeline.py` — rename stage, add 3 new imports, add tools to Stage 4, remove Naabu from Stage 9
- `shared/lib_webbh/playbooks.py` — update `PIPELINE_STAGES` dict and two `disabled_stages` lists
- `shared/config/1/playbook.json` — update stage name field
- `dashboard/src/lib/worker-stages.ts` — update display name + stageName
- `dashboard/src/components/campaign/WorkflowBuilder.tsx` — update stage name in array
- `tests/test_playbooks.py` — update two assertions
- `orchestrator/main.py` — update seeded job's `current_phase`
- `dashboard/e2e/tests/empty-states.spec.ts` — update test-id string
- `dashboard/e2e/tests/flows/worker-monitoring.spec.ts` — update three test-id strings
- `dashboard/e2e/tests/workflow-builder.spec.ts` — update test-id and comment
- `dashboard/e2e/tests/worker-control.spec.ts` — update text assertion

---

## Task 1: TDD — CTLogSearcher (tests)

**Files:**
- Create: `tests/test_ct_log_searcher.py`

- [ ] **Step 1: Write the test file**

```python
# tests/test_ct_log_searcher.py
"""Tests for CTLogSearcher — WSTG-INFO-04 CT log enumeration."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from workers.info_gathering.tools.ct_log_searcher import CTLogSearcher


@pytest.fixture
def tool():
    return CTLogSearcher()


@pytest.fixture
def mock_target():
    t = MagicMock()
    t.base_domain = "example.com"
    return t


class TestParseHostnames:
    def test_extracts_simple_subdomain(self, tool):
        data = [{"name_value": "sub.example.com"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "sub.example.com" in result

    def test_strips_wildcard_prefix(self, tool):
        data = [{"name_value": "*.example.com"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "example.com" in result
        assert "*.example.com" not in result

    def test_drops_out_of_scope_hostname(self, tool):
        data = [{"name_value": "other.org"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "other.org" not in result

    def test_handles_multiple_sans_per_record(self, tool):
        data = [{"name_value": "a.example.com\nb.example.com\nother.org"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "a.example.com" in result
        assert "b.example.com" in result
        assert "other.org" not in result

    def test_deduplicates_hostnames(self, tool):
        data = [
            {"name_value": "sub.example.com"},
            {"name_value": "sub.example.com"},
        ]
        result = tool._parse_hostnames(data, "example.com")
        assert result == {"sub.example.com"}

    def test_includes_base_domain_itself(self, tool):
        data = [{"name_value": "example.com"}]
        result = tool._parse_hostnames(data, "example.com")
        assert "example.com" in result

    def test_empty_data_returns_empty_set(self, tool):
        assert tool._parse_hostnames([], "example.com") == set()


class TestExecute:
    @pytest.mark.anyio
    async def test_saves_discovered_hostnames(self, tool, mock_target):
        tool._fetch_crtsh = AsyncMock(return_value=[
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"},
        ])
        saved = []

        async def fake_save_asset(target_id, asset_type, value, source, scope_manager=None, **kw):
            saved.append(value)
            return len(saved)

        tool.save_asset = fake_save_asset
        result = await tool.execute(1, target=mock_target, scope_manager=None)

        assert result["found"] == 2
        assert "api.example.com" in saved
        assert "example.com" in saved

    @pytest.mark.anyio
    async def test_skips_duplicate_assets(self, tool, mock_target):
        tool._fetch_crtsh = AsyncMock(return_value=[
            {"name_value": "sub.example.com"},
        ])
        # save_asset returns None when asset already exists
        tool.save_asset = AsyncMock(return_value=None)
        result = await tool.execute(1, target=mock_target, scope_manager=None)
        assert result["found"] == 0

    @pytest.mark.anyio
    async def test_returns_zero_when_fetch_returns_empty(self, tool, mock_target):
        tool._fetch_crtsh = AsyncMock(return_value=[])
        result = await tool.execute(1, target=mock_target, scope_manager=None)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_returns_zero_without_target(self, tool):
        result = await tool.execute(1)
        assert result == {"found": 0}


class TestFetchCrtsh:
    @pytest.mark.anyio
    async def test_returns_empty_list_on_non_200(self, tool):
        import aiohttp
        from unittest.mock import patch, AsyncMock, MagicMock

        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_get = MagicMock(return_value=mock_resp)

        mock_session = MagicMock()
        mock_session.get = mock_get
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("workers.info_gathering.tools.ct_log_searcher.aiohttp.ClientSession",
                   return_value=mock_session):
            result = await tool._fetch_crtsh("example.com")

        assert result == []

    @pytest.mark.anyio
    async def test_returns_empty_list_on_timeout(self, tool):
        import aiohttp
        from unittest.mock import patch

        with patch("workers.info_gathering.tools.ct_log_searcher.aiohttp.ClientSession",
                   side_effect=aiohttp.ClientConnectorError(None, OSError())):
            result = await tool._fetch_crtsh("example.com")

        assert result == []
```

- [ ] **Step 2: Run tests — confirm ImportError**

```
pytest tests/test_ct_log_searcher.py -v
```
Expected: `ImportError: cannot import name 'CTLogSearcher'`

---

## Task 2: Implement CTLogSearcher

**Files:**
- Create: `workers/info_gathering/tools/ct_log_searcher.py`

- [ ] **Step 1: Write the implementation**

```python
# workers/info_gathering/tools/ct_log_searcher.py
"""CTLogSearcher — enumerate hostnames from Certificate Transparency logs via crt.sh."""

import asyncio

import aiohttp

from workers.info_gathering.base_tool import InfoGatheringTool, logger


class CTLogSearcher(InfoGatheringTool):
    """Query crt.sh to discover hostnames from Certificate Transparency logs.

    Surfaces hostnames that Amass folds into its internal output as first-class
    Asset rows, including old dev/staging domains no longer in DNS.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        scope_manager = kwargs.get("scope_manager")
        if not target:
            return {"found": 0}

        data = await self._fetch_crtsh(target.base_domain)
        hostnames = self._parse_hostnames(data, target.base_domain)

        saved = 0
        for hostname in hostnames:
            asset_id = await self.save_asset(
                target_id, "subdomain", hostname, "ct_log_searcher",
                scope_manager=scope_manager,
            )
            if asset_id:
                saved += 1

        return {"found": saved}

    async def _fetch_crtsh(self, domain: str) -> list:
        """GET crt.sh JSON API for the domain. Returns raw record list or []."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"Accept": "application/json"}) as resp:
                    if resp.status != 200:
                        logger.warning(
                            "CTLogSearcher: crt.sh returned %s for %s", resp.status, domain
                        )
                        return []
                    return await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.warning("CTLogSearcher: request failed for %s: %s", domain, exc)
            return []
        except Exception as exc:
            logger.error("CTLogSearcher: unexpected error for %s: %s", domain, exc)
            return []

    def _parse_hostnames(self, data: list, domain: str) -> set[str]:
        """Extract unique in-scope hostnames from crt.sh records."""
        hostnames: set[str] = set()
        for record in data:
            for name in record.get("name_value", "").splitlines():
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                if name and (name.endswith(f".{domain}") or name == domain):
                    hostnames.add(name)
        return hostnames
```

- [ ] **Step 2: Run tests — confirm all pass**

```
pytest tests/test_ct_log_searcher.py -v
```
Expected: all tests `PASSED`

- [ ] **Step 3: Commit**

```bash
git add workers/info_gathering/tools/ct_log_searcher.py tests/test_ct_log_searcher.py
git commit -m "feat(info-gathering): add CTLogSearcher for WSTG-INFO-04 CT log enumeration"
```

---

## Task 3: TDD — AppPathEnumerator (tests)

**Files:**
- Create: `tests/test_app_path_enumerator.py`

- [ ] **Step 1: Write the test file**

```python
# tests/test_app_path_enumerator.py
"""Tests for AppPathEnumerator — WSTG-INFO-04 non-standard URL path discovery."""
from __future__ import annotations

import json
import os
import tempfile

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.app_path_enumerator import (
    AppPathEnumerator,
    APP_PATHS,
    HIT_CODES,
)


@pytest.fixture
def tool():
    return AppPathEnumerator()


@pytest.fixture
def mock_target():
    t = MagicMock()
    t.base_domain = "example.com"
    return t


def _write_ffuf_output(results: list) -> str:
    """Write a ffuf JSON output file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"results": results}, f)
        return f.name


class TestConstants:
    def test_wordlist_contains_key_app_paths(self):
        for path in ("admin", "portal", "webmail", "graphql", "swagger", "dashboard"):
            assert path in APP_PATHS

    def test_hit_codes_exclude_404(self):
        assert 404 not in HIT_CODES

    def test_hit_codes_include_auth_denials(self):
        assert 401 in HIT_CODES
        assert 403 in HIT_CODES

    def test_hit_codes_include_redirects(self):
        for code in (301, 302, 307, 308):
            assert code in HIT_CODES


class TestParseAndSave:
    @pytest.mark.anyio
    async def test_saves_200_hit_as_url_asset_and_observation(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/admin", "status": 200, "length": 1234, "redirectlocation": ""},
        ])
        saved_assets = []
        saved_obs = []

        async def fake_save_asset(target_id, asset_type, value, source, scope_manager=None, **kw):
            saved_assets.append({"type": asset_type, "value": value})
            return 42

        async def fake_save_observation(asset_id, **kw):
            saved_obs.append({"asset_id": asset_id, **kw})
            return 1

        tool.save_asset = fake_save_asset
        tool.save_observation = fake_save_observation

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 1}
        assert saved_assets[0] == {"type": "url", "value": "https://example.com/admin"}
        assert saved_obs[0]["asset_id"] == 42
        assert saved_obs[0]["status_code"] == 200

    @pytest.mark.anyio
    async def test_drops_404_responses(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/notfound", "status": 404, "length": 0, "redirectlocation": ""},
        ])
        tool.save_asset = AsyncMock(return_value=1)

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 0}
        tool.save_asset.assert_not_awaited()

    @pytest.mark.anyio
    async def test_saves_401_and_403_hits(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/admin", "status": 401, "length": 100, "redirectlocation": ""},
            {"url": "https://example.com/internal", "status": 403, "length": 200, "redirectlocation": ""},
        ])
        tool.save_asset = AsyncMock(side_effect=[42, 43])
        tool.save_observation = AsyncMock(return_value=1)

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 2}

    @pytest.mark.anyio
    async def test_records_redirect_url_in_observation(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/portal", "status": 302,
             "length": 0, "redirectlocation": "https://example.com/portal/login"},
        ])
        saved_obs = []

        tool.save_asset = AsyncMock(return_value=42)

        async def fake_save_observation(asset_id, **kw):
            saved_obs.append(kw)
            return 1

        tool.save_observation = fake_save_observation

        try:
            await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert saved_obs[0]["headers"]["redirect_url"] == "https://example.com/portal/login"

    @pytest.mark.anyio
    async def test_returns_zero_for_missing_output_file(self, tool):
        result = await tool._parse_and_save(1, "/tmp/no_such_ffuf_output_xyz.json", "example.com", None)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_skips_hit_when_save_asset_returns_none(self, tool):
        path = _write_ffuf_output([
            {"url": "https://example.com/admin", "status": 200, "length": 500, "redirectlocation": ""},
        ])
        tool.save_asset = AsyncMock(return_value=None)
        tool.save_observation = AsyncMock(return_value=1)

        try:
            result = await tool._parse_and_save(1, path, "example.com", None)
        finally:
            os.unlink(path)

        assert result == {"found": 0}
        tool.save_observation.assert_not_awaited()


class TestExecute:
    @pytest.mark.anyio
    async def test_returns_zero_without_target(self, tool):
        result = await tool.execute(1)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_returns_zero_when_ffuf_fails(self, tool, mock_target):
        tool.run_subprocess = AsyncMock(side_effect=Exception("ffuf not found"))
        result = await tool.execute(1, target=mock_target, scope_manager=None)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_cleans_up_temp_files_on_success(self, tool, mock_target):
        created_paths = []

        original_run = tool.run_subprocess

        async def capture_and_run(cmd, **kw):
            # Extract paths from the ffuf command
            for i, arg in enumerate(cmd):
                if arg in ("-w", "-o"):
                    created_paths.append(cmd[i + 1])
            # Write empty ffuf output to the output file
            with open(cmd[cmd.index("-o") + 1], "w") as f:
                json.dump({"results": []}, f)

        tool.run_subprocess = capture_and_run
        await tool.execute(1, target=mock_target, scope_manager=None)

        for path in created_paths:
            assert not os.path.exists(path), f"Temp file not cleaned up: {path}"
```

- [ ] **Step 2: Run tests — confirm ImportError**

```
pytest tests/test_app_path_enumerator.py -v
```
Expected: `ImportError: cannot import name 'AppPathEnumerator'`

---

## Task 4: Implement AppPathEnumerator

**Files:**
- Create: `workers/info_gathering/tools/app_path_enumerator.py`

- [ ] **Step 1: Write the implementation**

```python
# workers/info_gathering/tools/app_path_enumerator.py
"""AppPathEnumerator — probe target for applications at non-standard URL paths."""

import json
import os
import tempfile

from workers.info_gathering.base_tool import InfoGatheringTool, TOOL_TIMEOUT, logger

# Application-level path prefixes that commonly host distinct sub-applications.
# Focused on app-level entry points, not generic file/directory brute-forcing.
APP_PATHS: list[str] = [
    "admin", "portal", "webmail", "mail", "email", "dashboard", "api", "app",
    "backend", "console", "management", "wp-admin", "phpmyadmin", "cpanel",
    "login", "secure", "internal", "dev", "staging", "test", "demo", "backup",
    "monitor", "status", "health", "swagger", "graphql", "redoc", "docs",
    "api-docs", "helpdesk", "support", "crm", "erp", "git", "gitlab", "jira",
    "confluence", "jenkins", "sonar", "kibana", "grafana", "prometheus", "vault",
    "registry", "nexus", "artifactory", "wiki", "intranet", "vpn", "remote",
    "access", "connect", "extranet", "partner", "client", "customer", "shop",
    "store", "cart", "checkout", "payment", "billing", "invoice", "account",
    "profile", "settings", "config", "panel", "control", "manage", "report",
    "analytics", "metrics", "log", "logs", "audit", "trace", "debug", "error",
    "exception", "system", "service", "api-v1", "api-v2", "v1", "v2", "v3",
    "rest", "rpc", "soap", "graphiql",
]

# HTTP status codes that confirm a real application is present.
# 401/403 indicate access-controlled apps; 404 is excluded (nothing there).
HIT_CODES: set[int] = {200, 201, 301, 302, 307, 308, 401, 403}


class AppPathEnumerator(InfoGatheringTool):
    """Probe the target domain for distinct applications at non-standard path prefixes.

    Uses ffuf with a curated wordlist. Only persists paths that return meaningful
    HTTP responses (HIT_CODES), distinguishing real apps from 404s.
    """

    async def execute(self, target_id: int, **kwargs) -> dict:
        target = kwargs.get("target")
        scope_manager = kwargs.get("scope_manager")
        host = kwargs.get("host") or (target.base_domain if target else None)
        if not host:
            return {"found": 0}

        wordlist_path = None
        output_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as wl:
                wl.write("\n".join(APP_PATHS))
                wordlist_path = wl.name

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
                output_path = out.name

            cmd = [
                "ffuf",
                "-u", f"https://{host}/FUZZ",
                "-w", wordlist_path,
                "-mc", ",".join(str(c) for c in sorted(HIT_CODES)),
                "-o", output_path,
                "-of", "json",
                "-t", "20",
                "-timeout", "10",
                "-s",
            ]
            try:
                await self.run_subprocess(cmd, timeout=TOOL_TIMEOUT)
            except Exception as exc:
                logger.warning("AppPathEnumerator: ffuf failed for %s: %s", host, exc)
                return {"found": 0}

            return await self._parse_and_save(target_id, output_path, host, scope_manager)
        finally:
            for path in (wordlist_path, output_path):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    async def _parse_and_save(
        self, target_id: int, output_path: str, host: str, scope_manager
    ) -> dict:
        """Parse ffuf JSON output and persist hit paths as Assets + Observations."""
        try:
            with open(output_path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"found": 0}

        saved = 0
        for hit in data.get("results", []):
            status = hit.get("status")
            if status not in HIT_CODES:
                continue
            url = hit.get("url", "")
            if not url:
                continue

            asset_id = await self.save_asset(
                target_id, "url", url, "app_path_enumerator",
                scope_manager=scope_manager,
            )
            if not asset_id:
                continue

            await self.save_observation(
                asset_id,
                status_code=status,
                headers={
                    "content_length": hit.get("length", 0),
                    "redirect_url": hit.get("redirectlocation", ""),
                },
            )
            saved += 1

        return {"found": saved}
```

- [ ] **Step 2: Run tests — confirm all pass**

```
pytest tests/test_app_path_enumerator.py -v
```
Expected: all tests `PASSED`

- [ ] **Step 3: Commit**

```bash
git add workers/info_gathering/tools/app_path_enumerator.py tests/test_app_path_enumerator.py
git commit -m "feat(info-gathering): add AppPathEnumerator for WSTG-INFO-04 path discovery"
```

---

## Task 5: Update pipeline.py — rename stage, wire new tools, move Naabu

**Files:**
- Modify: `workers/info_gathering/pipeline.py`

- [ ] **Step 1: Add imports for new tools (after existing imports block)**

In `pipeline.py`, add these two imports alongside the existing ones (alphabetical order within the block):

```python
from .tools.app_path_enumerator import AppPathEnumerator
from .tools.ct_log_searcher import CTLogSearcher
```

- [ ] **Step 2: Update STAGES — rename Stage 4, add new tools, remove Naabu from Stage 9**

Replace the existing `STAGES` list with:

```python
STAGES = [
    Stage(name="search_engine_recon", section_id="4.1.1", tools=[DorkEngine, ArchiveProber, CacheProber, ShodanSearcher, CensysSearcher, SecurityTrailsSearcher]),
    Stage(name="web_server_fingerprint", section_id="4.1.2", tools=[
        LivenessProbe, BannerProbe, HeaderOrderProbe, MethodProbe,
        ErrorPageProbe, TLSProbe, WAFProbe, WhatWeb,
    ]),
    Stage(name="web_server_metafiles", section_id="4.1.3", tools=[MetafileParser, MetaTagAnalyzer]),
    Stage(name="enumerate_applications", section_id="4.1.4", tools=[
        Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns,
        VHostProber,
        Naabu,
        AppPathEnumerator,
        CTLogSearcher,
    ]),
    Stage(name="review_comments", section_id="4.1.5", tools=[CommentHarvester, MetadataExtractor]),
    Stage(name="identify_entry_points", section_id="4.1.6", tools=[FormMapper, Paramspider, Httpx]),
    Stage(name="map_execution_paths", section_id="4.1.7", tools=[Katana, Hakrawler]),
    Stage(name="fingerprint_framework", section_id="4.1.8", tools=[Wappalyzer, CookieFingerprinter, Webanalyze]),
    Stage(name="map_architecture", section_id="4.1.9", tools=[Waybackurls, ArchitectureModeler]),
    Stage(name="map_application", section_id="4.1.10", tools=[ApplicationMapper, AttackSurfaceAnalyzer]),
]
```

- [ ] **Step 3: Run existing pipeline tests**

```
pytest tests/test_info_gathering_base_tool.py tests/test_info_gathering_metafiles.py -v
```
Expected: all `PASSED`

- [ ] **Step 4: Commit**

```bash
git add workers/info_gathering/pipeline.py
git commit -m "feat(info-gathering): wire CTLogSearcher, AppPathEnumerator into Stage 4; move Naabu from Stage 9"
```

---

## Task 6: Rename enumerate_subdomains across all remaining files

**Files:**
- Modify: `shared/lib_webbh/playbooks.py`
- Modify: `shared/config/1/playbook.json`
- Modify: `dashboard/src/lib/worker-stages.ts`
- Modify: `dashboard/src/components/campaign/WorkflowBuilder.tsx`
- Modify: `tests/test_playbooks.py`
- Modify: `orchestrator/main.py`
- Modify: `dashboard/e2e/tests/empty-states.spec.ts`
- Modify: `dashboard/e2e/tests/flows/worker-monitoring.spec.ts`
- Modify: `dashboard/e2e/tests/workflow-builder.spec.ts`
- Modify: `dashboard/e2e/tests/worker-control.spec.ts`

- [ ] **Step 1: Update `shared/lib_webbh/playbooks.py`**

Line 19 — replace `"enumerate_subdomains"` with `"enumerate_applications"` in the `PIPELINE_STAGES` list:
```python
# Before
"enumerate_subdomains", "review_comments", "identify_entry_points",
# After
"enumerate_applications", "review_comments", "identify_entry_points",
```

Line 222 — update `disabled_stages` in the `standard` playbook override:
```python
# Before
"disabled_stages": ["search_engine_recon", "enumerate_subdomains"],
# After
"disabled_stages": ["search_engine_recon", "enumerate_applications"],
```

Line 248 — update `disabled_stages` in the `api_focused` playbook override:
```python
# Before
"search_engine_recon", "web_server_metafiles",
"enumerate_subdomains", "review_comments",
# After
"search_engine_recon", "web_server_metafiles",
"enumerate_applications", "review_comments",
```

- [ ] **Step 2: Update `shared/config/1/playbook.json`**

Change the `name` field on the Stage 4 entry:
```json
// Before
{ "name": "enumerate_subdomains", "enabled": true, "tool_timeout": 600 }
// After
{ "name": "enumerate_applications", "enabled": true, "tool_timeout": 600 }
```

- [ ] **Step 3: Update `dashboard/src/lib/worker-stages.ts`**

Line 13 — update both `name` (display) and `stageName` (machine name):
```typescript
// Before
{ id: "4", name: "Enumerate Subdomains", stageName: "enumerate_subdomains", sectionId: "WSTG-INFO-04" },
// After
{ id: "4", name: "Enumerate Applications", stageName: "enumerate_applications", sectionId: "WSTG-INFO-04" },
```

- [ ] **Step 4: Update `dashboard/src/components/campaign/WorkflowBuilder.tsx`**

Replace `"enumerate_subdomains"` with `"enumerate_applications"` in the stage name array (line 28).

- [ ] **Step 5: Update `tests/test_playbooks.py`**

Replace both occurrences of `"enumerate_subdomains"` with `"enumerate_applications"`:
```python
# Line 38 — before
disabled_stages=["search_engine_recon", "enumerate_subdomains"],
# After
disabled_stages=["search_engine_recon", "enumerate_applications"],

# Line 42 — before
assert {s.name for s in disabled} == {"search_engine_recon", "enumerate_subdomains"}
# After
assert {s.name for s in disabled} == {"search_engine_recon", "enumerate_applications"}
```

- [ ] **Step 6: Update `orchestrator/main.py`**

Line 2712 — update the seeded job's `current_phase`:
```python
# Before
"current_phase": "enumerate_subdomains", "status": "RUNNING",
# After
"current_phase": "enumerate_applications", "status": "RUNNING",
```

- [ ] **Step 7: Update `dashboard/e2e/tests/empty-states.spec.ts`**

Line 65 — update test-id string:
```typescript
// Before
.or(page.getByTestId("flow-monitor-stage-enumerate_subdomains"))
// After
.or(page.getByTestId("flow-monitor-stage-enumerate_applications"))
```

- [ ] **Step 8: Update `dashboard/e2e/tests/flows/worker-monitoring.spec.ts`**

Replace all three occurrences of `enumerate_subdomains` with `enumerate_applications`:
```typescript
// Lines 32, 69, 89 — before
page.getByTestId("flow-monitor-stage-enumerate_subdomains")
// After
page.getByTestId("flow-monitor-stage-enumerate_applications")
```

- [ ] **Step 9: Update `dashboard/e2e/tests/workflow-builder.spec.ts`**

Replace all occurrences:
```typescript
// Before (lines 78-80)
await expect(page.getByTestId("flow-monitor-stage-enumerate_subdomains")).toBeVisible({ timeout: 10_000 });
// The seeded job has status "RUNNING" with phase "enumerate_subdomains"
await expect(page.getByTestId("flow-monitor-status-enumerate_subdomains")).toContainText(/running/i);
// After
await expect(page.getByTestId("flow-monitor-stage-enumerate_applications")).toBeVisible({ timeout: 10_000 });
// The seeded job has status "RUNNING" with phase "enumerate_applications"
await expect(page.getByTestId("flow-monitor-status-enumerate_applications")).toContainText(/running/i);
```

- [ ] **Step 10: Update `dashboard/e2e/tests/worker-control.spec.ts`**

Line 75 — update text assertion:
```typescript
// Before
await expect(runningCard).toContainText("enumerate_subdomains");
// After
await expect(runningCard).toContainText("enumerate_applications");
```

- [ ] **Step 11: Run pytest to confirm Python changes are clean**

```
pytest tests/test_playbooks.py -v
```
Expected: all `PASSED`

- [ ] **Step 12: Commit all reference updates atomically**

```bash
git add \
  shared/lib_webbh/playbooks.py \
  shared/config/1/playbook.json \
  dashboard/src/lib/worker-stages.ts \
  dashboard/src/components/campaign/WorkflowBuilder.tsx \
  tests/test_playbooks.py \
  orchestrator/main.py \
  dashboard/e2e/tests/empty-states.spec.ts \
  dashboard/e2e/tests/flows/worker-monitoring.spec.ts \
  dashboard/e2e/tests/workflow-builder.spec.ts \
  dashboard/e2e/tests/worker-control.spec.ts
git commit -m "refactor(info-gathering): rename enumerate_subdomains → enumerate_applications across all files"
```

---

## Task 7: Full test suite verification

- [ ] **Step 1: Run all Python tests**

```
pytest -v
```
Expected: all `PASSED`. No failures.

- [ ] **Step 2: Verify no remaining enumerate_subdomains references in non-doc files**

```bash
grep -r "enumerate_subdomains" --include="*.py" --include="*.ts" --include="*.tsx" --include="*.json" . \
  --exclude-dir=docs --exclude-dir=node_modules
```
Expected: no output (zero matches).
