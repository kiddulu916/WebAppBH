# WSTG-INFO-05 Stage 5 Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three new WSTG-INFO-05 leakage tools (JsSecretScanner, SourceMapProber, RedirectBodyInspector), fix MetadataExtractor's blocking subprocess, and split Stage 7 to add a `review_comments_deep` pass after the crawlers.

**Architecture:** DB-first — each tool queries URL assets already in the database, falls back to root page parsing when the DB is sparse, and stores `tech_stack={"_source": "<toolname>"}` on Observation records for idempotency. JsSecretScanner spawns trufflehog and gitleaks via `asyncio.create_subprocess_exec` on downloaded JS files. SourceMapProber issues HEAD requests to `<url>.map`. RedirectBodyInspector fetches without auto-redirect and regex-scans 3xx bodies.

**Tech Stack:** Python 3.11, aiohttp, asyncio, SQLAlchemy async (JSONB), trufflehog v3, gitleaks v8, pytest + AsyncMock, Docker.

**Spec:** `docs/superpowers/specs/2026-05-15-wstg-info05-stage5-redesign-design.md`

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Modify | `workers/info_gathering/tools/metadata_extractor.py` | Replace `subprocess.run` with `asyncio.create_subprocess_exec` |
| Create | `workers/info_gathering/tools/source_map_prober.py` | SourceMapProber — detect exposed `.map` files |
| Create | `workers/info_gathering/tools/redirect_body_inspector.py` | RedirectBodyInspector — scan 3xx response bodies |
| Create | `workers/info_gathering/tools/js_secret_scanner.py` | JsSecretScanner — trufflehog + gitleaks on JS files |
| Create | `tests/test_info_gathering_wstg_info05.py` | Tests for all four changes |
| Modify | `workers/info_gathering/pipeline.py` | Import new tools, update Stage 5, add `review_comments_deep` |
| Modify | `workers/info_gathering/concurrency.py` | Add TOOL_WEIGHTS for three new tools |
| Modify | `docker/Dockerfile.info_gathering` | Install trufflehog and gitleaks binaries |

---

## Task 1: Fix MetadataExtractor — Replace Blocking Subprocess

**Files:**
- Modify: `workers/info_gathering/tools/metadata_extractor.py`
- Create: `tests/test_info_gathering_wstg_info05.py`

The current `_extract_metadata` method calls `subprocess.run(["exiftool", ...])` (a blocking call) inside an async function, which freezes the event loop for the duration of exiftool execution. Replace with `asyncio.create_subprocess_exec`.

- [ ] **Step 1.1: Create the test file and write a failing test**

Create `tests/test_info_gathering_wstg_info05.py`:

```python
# tests/test_info_gathering_wstg_info05.py
"""Tests for WSTG-INFO-05 Stage 5 tools."""
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.tools.metadata_extractor import MetadataExtractor


class TestMetadataExtractorAsyncSubprocess:
    @pytest.mark.anyio
    async def test_exiftool_called_via_create_subprocess_exec(self, tmp_path):
        """_extract_metadata must use asyncio.create_subprocess_exec, not subprocess.run."""
        tool = MetadataExtractor()
        fake_url = "https://example.com/report.pdf"

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b'[{"Author": "Alice", "Creator": "Word"}]', b"")
        )
        mock_proc.returncode = 0

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=b"%PDF fake content")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec, \
             patch("aiohttp.ClientSession") as mock_http, \
             patch("tempfile.NamedTemporaryFile") as mock_tmp, \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"):

            mock_http.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_resp
            fake_file = MagicMock()
            fake_file.name = "/tmp/test_doc.pdf"
            mock_tmp.return_value.__enter__.return_value = fake_file

            result = await tool._extract_metadata(fake_url)

        # Must have called asyncio.create_subprocess_exec with exiftool
        mock_exec.assert_called_once()
        args = mock_exec.call_args[0]
        assert args[0] == "exiftool"
        assert args[1] == "-json"
        assert result == {"Author": "Alice", "Creator": "Word"}

    @pytest.mark.anyio
    async def test_returns_empty_dict_on_nonzero_returncode(self, tmp_path):
        """_extract_metadata returns {} when exiftool exits non-zero."""
        tool = MetadataExtractor()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
        mock_proc.returncode = 1

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=b"content")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("aiohttp.ClientSession") as mock_http, \
             patch("tempfile.NamedTemporaryFile") as mock_tmp, \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"):

            mock_http.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_resp
            fake_file = MagicMock()
            fake_file.name = "/tmp/test_doc.pdf"
            mock_tmp.return_value.__enter__.return_value = fake_file

            result = await tool._extract_metadata("https://example.com/doc.pdf")

        assert result == {}
```

- [ ] **Step 1.2: Run the test to verify it fails**

```
pytest tests/test_info_gathering_wstg_info05.py::TestMetadataExtractorAsyncSubprocess -v
```

Expected: FAIL — `asyncio.create_subprocess_exec` is not called; `subprocess.run` is called instead.

- [ ] **Step 1.3: Apply the fix to metadata_extractor.py**

In `workers/info_gathering/tools/metadata_extractor.py`, replace the `_extract_metadata` method. The old inner block (inside the `if resp.status == 200:` branch) is:

```python
                        try:
                            import subprocess
                            result = subprocess.run(
                                ["exiftool", "-json", tmp_path],
                                capture_output=True, text=True, timeout=30
                            )
                            if result.returncode == 0:
                                import json
                                data = json.loads(result.stdout)
                                return data[0] if data else {}
                        finally:
                            if os.path.exists(tmp_path):
                                os.unlink(tmp_path)
```

Replace with:

```python
                        try:
                            proc = await asyncio.create_subprocess_exec(
                                "exiftool", "-json", tmp_path,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            stdout_bytes, _ = await asyncio.wait_for(
                                proc.communicate(), timeout=30
                            )
                            if proc.returncode == 0:
                                import json
                                data = json.loads(stdout_bytes.decode("utf-8", errors="replace"))
                                return data[0] if data else {}
                        except asyncio.TimeoutError:
                            pass
                        finally:
                            if os.path.exists(tmp_path):
                                os.unlink(tmp_path)
```

Also add `import asyncio` at the top of the file (after the existing imports).

- [ ] **Step 1.4: Run the tests to verify they pass**

```
pytest tests/test_info_gathering_wstg_info05.py::TestMetadataExtractorAsyncSubprocess -v
```

Expected: PASS (both tests green).

- [ ] **Step 1.5: Commit**

```bash
git add workers/info_gathering/tools/metadata_extractor.py tests/test_info_gathering_wstg_info05.py
git commit -m "fix(info-gathering): replace blocking subprocess.run in MetadataExtractor"
```

---

## Task 2: Implement SourceMapProber

**Files:**
- Create: `workers/info_gathering/tools/source_map_prober.py`
- Modify: `tests/test_info_gathering_wstg_info05.py`

Probes discovered `.js`/`.css` assets for accessible `.map` files, saving an Observation (as processed marker) and a Vulnerability for each exposed map.

- [ ] **Step 2.1: Add failing tests to the test file**

Append to `tests/test_info_gathering_wstg_info05.py`:

```python
from workers.info_gathering.tools.source_map_prober import SourceMapProber


class TestSourceMapProber:
    @pytest.mark.anyio
    async def test_saves_vuln_when_map_exposed(self):
        """SourceMapProber saves a Vulnerability when the .map URL returns 200."""
        tool = SourceMapProber()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_candidates", new_callable=AsyncMock,
                          return_value=[("https://example.com/app.js", 1)]), \
             patch.object(tool, "_probe_map", new_callable=AsyncMock, return_value=True), \
             patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=10) as save_obs, \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock, return_value=5) as save_vuln:

            await tool.execute(target_id=1, target=target)

        save_obs.assert_awaited_once()
        obs_kwargs = save_obs.call_args.kwargs
        assert obs_kwargs["asset_id"] == 1
        assert obs_kwargs["tech_stack"]["_source"] == "source_map_prober"
        assert obs_kwargs["tech_stack"]["map_url"] == "https://example.com/app.js.map"

        save_vuln.assert_awaited_once()
        vuln_kwargs = save_vuln.call_args.kwargs
        assert vuln_kwargs["severity"] == "medium"
        assert vuln_kwargs["vuln_type"] == "source_map_exposure"
        assert vuln_kwargs["evidence"]["map_url"] == "https://example.com/app.js.map"

    @pytest.mark.anyio
    async def test_no_vuln_when_map_not_exposed(self):
        """SourceMapProber does not save a Vulnerability when .map returns non-200."""
        tool = SourceMapProber()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_candidates", new_callable=AsyncMock,
                          return_value=[("https://example.com/app.js", 1)]), \
             patch.object(tool, "_probe_map", new_callable=AsyncMock, return_value=False), \
             patch.object(tool, "save_observation", new_callable=AsyncMock) as save_obs, \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock) as save_vuln:

            await tool.execute(target_id=1, target=target)

        save_obs.assert_not_awaited()
        save_vuln.assert_not_awaited()

    @pytest.mark.anyio
    async def test_falls_back_to_root_when_db_empty(self):
        """SourceMapProber calls _candidates_from_root when _get_candidates returns []."""
        tool = SourceMapProber()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_candidates", new_callable=AsyncMock, return_value=[]), \
             patch.object(tool, "_candidates_from_root", new_callable=AsyncMock,
                          return_value=[("https://example.com/main.js", 2)]) as from_root, \
             patch.object(tool, "_probe_map", new_callable=AsyncMock, return_value=False), \
             patch.object(tool, "save_observation", new_callable=AsyncMock), \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock):

            await tool.execute(target_id=1, target=target)

        from_root.assert_awaited_once_with("example.com", 1)

    @pytest.mark.anyio
    async def test_probe_map_returns_true_on_200(self):
        """_probe_map returns True when HEAD to .map URL yields 200."""
        tool = SourceMapProber()
        map_url = "https://example.com/app.js.map"

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_http = AsyncMock()
        mock_http.head.return_value = mock_resp
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_http):
            result = await tool._probe_map(map_url)

        assert result is True

    @pytest.mark.anyio
    async def test_probe_map_returns_false_on_404(self):
        """_probe_map returns False when HEAD to .map URL yields 404."""
        tool = SourceMapProber()

        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_http = AsyncMock()
        mock_http.head.return_value = mock_resp
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_http):
            result = await tool._probe_map("https://example.com/app.js.map")

        assert result is False
```

- [ ] **Step 2.2: Run the tests to verify they fail**

```
pytest tests/test_info_gathering_wstg_info05.py::TestSourceMapProber -v
```

Expected: ImportError or AttributeError — `source_map_prober` module does not exist yet.

- [ ] **Step 2.3: Create workers/info_gathering/tools/source_map_prober.py**

```python
# workers/info_gathering/tools/source_map_prober.py
"""SourceMapProber — detect exposed source map files (WSTG-INFO-05)."""
import re

import aiohttp
from sqlalchemy import or_, select

from lib_webbh import Asset, Observation, get_session
from workers.info_gathering.base_tool import InfoGatheringTool


class SourceMapProber(InfoGatheringTool):
    """Check whether .map files are publicly accessible for discovered JS/CSS assets."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        candidates = await self._get_candidates(target_id)
        if not candidates:
            candidates = await self._candidates_from_root(target.base_domain, target_id)

        for url, asset_id in candidates:
            map_url = f"{url}.map"
            if not await self._probe_map(map_url):
                continue
            await self.save_observation(
                asset_id=asset_id,
                tech_stack={"_source": "source_map_prober", "map_url": map_url},
            )
            await self.save_vulnerability(
                target_id=target_id,
                asset_id=asset_id,
                severity="medium",
                title=f"Source map file exposed: {map_url}",
                description=(
                    f"The source map at {map_url} is publicly accessible. "
                    "This reveals original (unminified) source code, file paths, "
                    "and internal application structure to attackers."
                ),
                source_tool="source_map_prober",
                section_id="4.1.5",
                vuln_type="source_map_exposure",
                evidence={"map_url": map_url, "js_url": url},
            )

    async def _get_candidates(self, target_id: int) -> list[tuple[str, int]]:
        """Return (url, asset_id) pairs for .js/.css assets not yet probed."""
        async with get_session() as session:
            stmt = (
                select(Asset.asset_value, Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                    or_(
                        Asset.asset_value.like("%.js"),
                        Asset.asset_value.like("%.css"),
                    ),
                )
            )
            result = await session.execute(stmt)
            all_assets = result.all()
            if not all_assets:
                return []

            asset_ids = [row[1] for row in all_assets]
            processed_stmt = (
                select(Observation.asset_id)
                .where(
                    Observation.asset_id.in_(asset_ids),
                    Observation.tech_stack["_source"].astext == "source_map_prober",
                )
            )
            processed_result = await session.execute(processed_stmt)
            processed_ids = {row[0] for row in processed_result.all()}

            return [(url, aid) for url, aid in all_assets if aid not in processed_ids]

    async def _candidates_from_root(self, base_domain: str, target_id: int) -> list[tuple[str, int]]:
        """Parse root page HTML for .js/.css links; create Asset records."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://{base_domain}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
        except Exception:
            return []

        found = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
        found += re.findall(r'<link[^>]+href=["\']([^"\']+\.css)["\']', html)

        results = []
        for href in found:
            full_url = (
                href if href.startswith("http")
                else f"https://{base_domain}{href if href.startswith('/') else '/' + href}"
            )
            aid = await self.save_asset(target_id, "url", full_url, "source_map_prober")
            if aid is None:
                async with get_session() as session:
                    stmt = select(Asset.id).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == full_url,
                    )
                    r = await session.execute(stmt)
                    aid = r.scalar_one_or_none()
            if aid:
                results.append((full_url, aid))
        return results

    async def _probe_map(self, map_url: str) -> bool:
        """Return True if the .map URL responds HTTP 200."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.head(map_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return True
                    if resp.status not in (405, 501):
                        return False
                # HEAD not supported — fall back to GET
                async with http.get(
                    map_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False
```

- [ ] **Step 2.4: Run the tests to verify they pass**

```
pytest tests/test_info_gathering_wstg_info05.py::TestSourceMapProber -v
```

Expected: all 5 tests PASS.

- [ ] **Step 2.5: Commit**

```bash
git add workers/info_gathering/tools/source_map_prober.py tests/test_info_gathering_wstg_info05.py
git commit -m "feat(info-gathering): add SourceMapProber for WSTG-INFO-05 source map detection"
```

---

## Task 3: Implement RedirectBodyInspector

**Files:**
- Create: `workers/info_gathering/tools/redirect_body_inspector.py`
- Modify: `tests/test_info_gathering_wstg_info05.py`

Fetches URL assets without auto-following redirects, captures 3xx response bodies, and regex-scans them for sensitive content patterns.

- [ ] **Step 3.1: Add failing tests**

Append to `tests/test_info_gathering_wstg_info05.py`:

```python
from workers.info_gathering.tools.redirect_body_inspector import RedirectBodyInspector


class TestRedirectBodyInspector:
    @pytest.mark.anyio
    async def test_saves_vuln_on_sensitive_redirect_body(self):
        """RedirectBodyInspector saves Vulnerability when redirect body contains credentials."""
        tool = RedirectBodyInspector()
        target = MagicMock(base_domain="example.com")

        with patch.object(tool, "_get_url_assets", new_callable=AsyncMock,
                          return_value=[("https://example.com/login", 1)]), \
             patch.object(tool, "_inspect", new_callable=AsyncMock) as mock_inspect:

            await tool.execute(target_id=1, target=target)

        mock_inspect.assert_awaited_once_with("https://example.com/login", 1, 1)

    @pytest.mark.anyio
    async def test_scan_body_detects_credential_keyword(self):
        """_scan_body returns matches for credential-like strings."""
        tool = RedirectBodyInspector()
        body = 'Redirecting... api_key=supersecret123'
        matches = tool._scan_body(body)
        types = [t for _, t in matches]
        assert "credential_keyword" in types

    @pytest.mark.anyio
    async def test_scan_body_detects_internal_ip(self):
        """_scan_body returns matches for RFC-1918 IP addresses."""
        tool = RedirectBodyInspector()
        body = "Server at 10.0.1.42 is unavailable"
        matches = tool._scan_body(body)
        types = [t for _, t in matches]
        assert "internal_ip" in types

    @pytest.mark.anyio
    async def test_scan_body_detects_stack_trace(self):
        """_scan_body returns matches for Python/Java stack trace patterns."""
        tool = RedirectBodyInspector()
        body = "Traceback (most recent call last):\n  File 'app.py', line 42"
        matches = tool._scan_body(body)
        types = [t for _, t in matches]
        assert "stack_trace" in types

    @pytest.mark.anyio
    async def test_scan_body_returns_empty_for_clean_body(self):
        """_scan_body returns [] for body with no sensitive patterns."""
        tool = RedirectBodyInspector()
        body = "302 Found. Please follow the redirect."
        matches = tool._scan_body(body)
        assert matches == []

    @pytest.mark.anyio
    async def test_saves_observation_always_saves_vuln_only_on_match(self):
        """_inspect saves Observation unconditionally; Vulnerability only when patterns match."""
        tool = RedirectBodyInspector()

        mock_status = 302
        mock_body = "password=hunter2"

        with patch.object(tool, "save_observation", new_callable=AsyncMock) as save_obs, \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock) as save_vuln, \
             patch("aiohttp.ClientSession") as mock_http:

            mock_resp = AsyncMock()
            mock_resp.status = mock_status
            mock_resp.text = AsyncMock(return_value=mock_body)
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=False)
            mock_http_inst = AsyncMock()
            mock_http_inst.get.return_value = mock_resp
            mock_http_inst.__aenter__ = AsyncMock(return_value=mock_http_inst)
            mock_http_inst.__aexit__ = AsyncMock(return_value=False)
            mock_http.return_value = mock_http_inst

            await tool._inspect("https://example.com/login", asset_id=1, target_id=1)

        save_obs.assert_awaited_once()
        assert save_obs.call_args.kwargs["tech_stack"]["_source"] == "redirect_body_inspector"
        save_vuln.assert_awaited_once()
        assert save_vuln.call_args.kwargs["vuln_type"] == "redirect_body_leakage"
```

- [ ] **Step 3.2: Run the tests to verify they fail**

```
pytest tests/test_info_gathering_wstg_info05.py::TestRedirectBodyInspector -v
```

Expected: ImportError — module does not exist yet.

- [ ] **Step 3.3: Create workers/info_gathering/tools/redirect_body_inspector.py**

```python
# workers/info_gathering/tools/redirect_body_inspector.py
"""RedirectBodyInspector — detect sensitive content in 3xx redirect response bodies (WSTG-INFO-05)."""
import re

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, Observation, get_session
from workers.info_gathering.base_tool import InfoGatheringTool

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r'\b(?:password|passwd|secret|api_key|apikey|token|auth)\s*[:=]\s*\S+', re.I),
        "credential_keyword",
    ),
    (
        re.compile(
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'
            r'|192\.168\.\d+\.\d+'
        ),
        "internal_ip",
    ),
    (
        re.compile(
            r'Traceback \(most recent call last\)'
            r'|at\s+[\w.$]+\([\w.:]+:\d+\)'
            r'|Exception in thread'
        ),
        "stack_trace",
    ),
]


class RedirectBodyInspector(InfoGatheringTool):
    """Fetch URLs without auto-redirect; scan 3xx response bodies for sensitive content."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        candidates = await self._get_url_assets(target_id)
        if not candidates:
            candidates = await self._urls_from_root(target.base_domain, target_id)

        for url, asset_id in candidates[:50]:
            await self._inspect(url, asset_id, target_id)

    async def _get_url_assets(self, target_id: int) -> list[tuple[str, int]]:
        """Return (url, asset_id) for URL assets not yet inspected."""
        async with get_session() as session:
            stmt = (
                select(Asset.asset_value, Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                )
            )
            result = await session.execute(stmt)
            all_assets = result.all()
            if not all_assets:
                return []

            asset_ids = [row[1] for row in all_assets]
            processed_stmt = (
                select(Observation.asset_id)
                .where(
                    Observation.asset_id.in_(asset_ids),
                    Observation.tech_stack["_source"].astext == "redirect_body_inspector",
                )
            )
            processed_result = await session.execute(processed_stmt)
            processed_ids = {row[0] for row in processed_result.all()}

            return [(url, aid) for url, aid in all_assets if aid not in processed_ids]

    async def _urls_from_root(self, base_domain: str, target_id: int) -> list[tuple[str, int]]:
        """Parse root page links; create Asset records for fallback URLs."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://{base_domain}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
        except Exception:
            return []

        hrefs = re.findall(r'href=["\']([^"\'#?][^"\']*)["\']', html)
        results = []
        for href in hrefs[:50]:
            full_url = (
                href if href.startswith("http")
                else f"https://{base_domain}{href if href.startswith('/') else '/' + href}"
            )
            aid = await self.save_asset(target_id, "url", full_url, "redirect_body_inspector")
            if aid is None:
                async with get_session() as session:
                    stmt = select(Asset.id).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == full_url,
                    )
                    r = await session.execute(stmt)
                    aid = r.scalar_one_or_none()
            if aid:
                results.append((full_url, aid))
        return results

    async def _inspect(self, url: str, asset_id: int, target_id: int) -> None:
        """Fetch url without redirect; save observation and vulnerability if body leaks data."""
        status = None
        body = None
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    if status not in range(300, 400):
                        return
                    body = await resp.text(errors="replace")
        except Exception:
            return

        if body is None:
            return

        await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_source": "redirect_body_inspector", "status": status},
        )

        matches = self._scan_body(body)
        if not matches:
            return

        match_types = sorted({t for _, t in matches})
        await self.save_vulnerability(
            target_id=target_id,
            asset_id=asset_id,
            severity="low",
            title=f"Sensitive content in redirect response body: {url}",
            description=(
                f"The {status} redirect response for {url} contains sensitive patterns: "
                f"{', '.join(match_types)}. Browsers discard redirect bodies silently, "
                "so developers often overlook this leakage vector."
            ),
            source_tool="redirect_body_inspector",
            section_id="4.1.5",
            vuln_type="redirect_body_leakage",
            evidence={
                "url": url,
                "status_code": status,
                "matches": [{"type": t, "value": v[:200]} for v, t in matches],
            },
        )

    def _scan_body(self, body: str) -> list[tuple[str, str]]:
        """Return list of (matched_string, pattern_label) for all matches in body."""
        results = []
        for pattern, label in _PATTERNS:
            for m in pattern.finditer(body):
                results.append((m.group(), label))
        return results
```

- [ ] **Step 3.4: Run the tests to verify they pass**

```
pytest tests/test_info_gathering_wstg_info05.py::TestRedirectBodyInspector -v
```

Expected: all 6 tests PASS.

- [ ] **Step 3.5: Commit**

```bash
git add workers/info_gathering/tools/redirect_body_inspector.py tests/test_info_gathering_wstg_info05.py
git commit -m "feat(info-gathering): add RedirectBodyInspector for WSTG-INFO-05 redirect leakage"
```

---

## Task 4: Implement JsSecretScanner

**Files:**
- Create: `workers/info_gathering/tools/js_secret_scanner.py`
- Modify: `tests/test_info_gathering_wstg_info05.py`

Downloads discovered JS files to a temp directory, runs trufflehog and gitleaks on the directory, deduplicates findings by secret value, and saves each unique finding as a Vulnerability.

- [ ] **Step 4.1: Add failing tests**

Append to `tests/test_info_gathering_wstg_info05.py`:

```python
from workers.info_gathering.tools.js_secret_scanner import JsSecretScanner


class TestJsSecretScanner:
    def test_parse_trufflehog_extracts_findings(self):
        """_parse_trufflehog parses NDJSON output from trufflehog filesystem."""
        tool = JsSecretScanner()
        ndjson = (
            '{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":false,'
            '"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/app.js"}}}}\n'
            '{"DetectorName":"GitHub","Raw":"ghp_abc123","Verified":true,'
            '"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/lib.js"}}}}\n'
        )
        findings = tool._parse_trufflehog(ndjson)
        assert len(findings) == 2
        assert findings[0]["tool"] == "trufflehog"
        assert findings[0]["detector"] == "AWS"
        assert findings[0]["secret"] == "AKIAIOSFODNN7EXAMPLE"
        assert findings[0]["verified"] is False
        assert findings[1]["secret"] == "ghp_abc123"
        assert findings[1]["verified"] is True

    def test_parse_trufflehog_skips_invalid_lines(self):
        """_parse_trufflehog skips non-JSON lines gracefully."""
        tool = JsSecretScanner()
        output = "not json\n{\"DetectorName\":\"AWS\",\"Raw\":\"key\",\"Verified\":false,\"SourceMetadata\":{}}\n"
        findings = tool._parse_trufflehog(output)
        assert len(findings) == 1

    def test_parse_gitleaks_extracts_findings(self, tmp_path):
        """_parse_gitleaks reads the JSON report file gitleaks writes."""
        tool = JsSecretScanner()
        report = tmp_path / "report.json"
        report.write_text(json.dumps([
            {"RuleID": "aws-access-key", "Secret": "AKIAIOSFODNN7EXAMPLE", "File": "/tmp/app.js"},
            {"RuleID": "github-pat", "Secret": "ghp_xyz", "File": "/tmp/lib.js"},
        ]))
        findings = tool._parse_gitleaks(str(report))
        assert len(findings) == 2
        assert findings[0]["tool"] == "gitleaks"
        assert findings[0]["detector"] == "aws-access-key"
        assert findings[0]["secret"] == "AKIAIOSFODNN7EXAMPLE"
        assert findings[0]["verified"] is False

    def test_parse_gitleaks_returns_empty_on_missing_file(self):
        """_parse_gitleaks returns [] when the report file does not exist."""
        tool = JsSecretScanner()
        findings = tool._parse_gitleaks("/nonexistent/path/report.json")
        assert findings == []

    def test_deduplicate_removes_same_secret(self):
        """_deduplicate keeps only the first occurrence of each secret value."""
        tool = JsSecretScanner()
        findings = [
            {"tool": "trufflehog", "secret": "AKIA123", "detector": "AWS", "verified": False, "file": "a.js"},
            {"tool": "gitleaks",   "secret": "AKIA123", "detector": "aws-access-key", "verified": False, "file": "a.js"},
            {"tool": "trufflehog", "secret": "ghp_xyz", "detector": "GitHub", "verified": True, "file": "b.js"},
        ]
        unique = tool._deduplicate(findings)
        assert len(unique) == 2
        assert unique[0]["secret"] == "AKIA123"
        assert unique[1]["secret"] == "ghp_xyz"

    @pytest.mark.anyio
    async def test_execute_saves_observation_and_vuln(self):
        """execute() saves one Observation per JS asset and one Vulnerability per unique finding."""
        tool = JsSecretScanner()
        target = MagicMock(base_domain="example.com")

        th_output = '{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/js_0.js"}}}}\n'

        with patch.object(tool, "_get_js_assets", new_callable=AsyncMock,
                          return_value=[("https://example.com/app.js", 1)]), \
             patch.object(tool, "_download_js", new_callable=AsyncMock,
                          return_value=["/tmp/js_0.js"]), \
             patch.object(tool, "run_subprocess", new_callable=AsyncMock,
                          side_effect=[th_output, ""]), \
             patch.object(tool, "_parse_gitleaks", return_value=[]), \
             patch.object(tool, "save_observation", new_callable=AsyncMock, return_value=10) as save_obs, \
             patch.object(tool, "save_vulnerability", new_callable=AsyncMock, return_value=5) as save_vuln:

            with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                mock_tmpdir.return_value.__enter__ = MagicMock(return_value="/tmp/fakedir")
                mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)
                await tool.execute(target_id=1, target=target)

        save_obs.assert_awaited_once()
        obs_kwargs = save_obs.call_args.kwargs
        assert obs_kwargs["asset_id"] == 1
        assert obs_kwargs["tech_stack"]["_source"] == "js_secret_scanner"

        save_vuln.assert_awaited_once()
        vuln_kwargs = save_vuln.call_args.kwargs
        assert vuln_kwargs["vuln_type"] == "hardcoded_secret"
        assert vuln_kwargs["severity"] == "medium"
        assert "AKIAIOSFODNN7EXAMPLE" in vuln_kwargs["evidence"]["secret"]
```

- [ ] **Step 4.2: Run the tests to verify they fail**

```
pytest tests/test_info_gathering_wstg_info05.py::TestJsSecretScanner -v
```

Expected: ImportError — module does not exist yet.

- [ ] **Step 4.3: Create workers/info_gathering/tools/js_secret_scanner.py**

```python
# workers/info_gathering/tools/js_secret_scanner.py
"""JsSecretScanner — find hardcoded secrets in JS files via trufflehog and gitleaks (WSTG-INFO-05)."""
import json
import os
import re
import tempfile
from pathlib import Path

import aiohttp
from sqlalchemy import select

from lib_webbh import Asset, Observation, get_session
from workers.info_gathering.base_tool import InfoGatheringTool


class JsSecretScanner(InfoGatheringTool):
    """Download JS assets and scan them with trufflehog and gitleaks for hardcoded secrets."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        candidates = await self._get_js_assets(target_id)
        if not candidates:
            candidates = await self._js_from_root(target.base_domain, target_id)
        if not candidates:
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            downloaded = await self._download_js(candidates, tmpdir)
            if not downloaded:
                return

            th_output = ""
            gl_report = os.path.join(tmpdir, "gl_report.json")

            try:
                th_output = await self.run_subprocess(
                    ["trufflehog", "filesystem", tmpdir, "--json", "--no-update"],
                    timeout=120,
                )
            except Exception:
                pass

            try:
                await self.run_subprocess(
                    [
                        "gitleaks", "detect",
                        "--source", tmpdir,
                        "--no-git",
                        "--report-format", "json",
                        "--report-path", gl_report,
                        "--exit-code", "0",
                    ],
                    timeout=120,
                )
            except Exception:
                pass

            findings = self._deduplicate(
                self._parse_trufflehog(th_output) + self._parse_gitleaks(gl_report)
            )

            for _, asset_id in candidates:
                await self.save_observation(
                    asset_id=asset_id,
                    tech_stack={"_source": "js_secret_scanner", "secrets_found": len(findings)},
                )

            for finding in findings:
                await self.save_vulnerability(
                    target_id=target_id,
                    severity="medium",
                    title=f"Hardcoded secret in JavaScript: {finding['detector']}",
                    description=(
                        f"{finding['tool']} detected a {finding['detector']} secret "
                        f"in {finding['file']}. Verified: {finding['verified']}."
                    ),
                    source_tool="js_secret_scanner",
                    section_id="4.1.5",
                    vuln_type="hardcoded_secret",
                    evidence=finding,
                )

    async def _get_js_assets(self, target_id: int) -> list[tuple[str, int]]:
        """Return (url, asset_id) for .js assets not yet processed by this tool."""
        async with get_session() as session:
            stmt = (
                select(Asset.asset_value, Asset.id)
                .where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "url",
                    Asset.asset_value.like("%.js"),
                )
            )
            result = await session.execute(stmt)
            all_assets = result.all()
            if not all_assets:
                return []

            asset_ids = [row[1] for row in all_assets]
            processed_stmt = (
                select(Observation.asset_id)
                .where(
                    Observation.asset_id.in_(asset_ids),
                    Observation.tech_stack["_source"].astext == "js_secret_scanner",
                )
            )
            processed_result = await session.execute(processed_stmt)
            processed_ids = {row[0] for row in processed_result.all()}

            return [(url, aid) for url, aid in all_assets if aid not in processed_ids]

    async def _js_from_root(self, base_domain: str, target_id: int) -> list[tuple[str, int]]:
        """Parse root page <script src> links; create Asset records."""
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://{base_domain}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
        except Exception:
            return []

        hrefs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
        results = []
        for href in hrefs[:20]:
            full_url = (
                href if href.startswith("http")
                else f"https://{base_domain}{href if href.startswith('/') else '/' + href}"
            )
            aid = await self.save_asset(target_id, "url", full_url, "js_secret_scanner")
            if aid is None:
                async with get_session() as session:
                    stmt = select(Asset.id).where(
                        Asset.target_id == target_id,
                        Asset.asset_value == full_url,
                    )
                    r = await session.execute(stmt)
                    aid = r.scalar_one_or_none()
            if aid:
                results.append((full_url, aid))
        return results

    async def _download_js(
        self, candidates: list[tuple[str, int]], tmpdir: str
    ) -> list[str]:
        """Download JS files into tmpdir; return list of written file paths."""
        downloaded = []
        async with aiohttp.ClientSession() as http:
            for i, (url, _) in enumerate(candidates[:20]):
                try:
                    async with http.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            content = await resp.text(errors="replace")
                            path = os.path.join(tmpdir, f"js_{i}.js")
                            Path(path).write_text(content, encoding="utf-8")
                            downloaded.append(path)
                except Exception:
                    continue
        return downloaded

    def _parse_trufflehog(self, output: str) -> list[dict]:
        """Parse trufflehog --json NDJSON output into normalised finding dicts."""
        findings = []
        for line in output.strip().splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "tool": "trufflehog",
                    "detector": obj.get("DetectorName", "unknown"),
                    "secret": obj.get("Raw", ""),
                    "verified": obj.get("Verified", False),
                    "file": (
                        (obj.get("SourceMetadata") or {})
                        .get("Data", {})
                        .get("Filesystem", {})
                        .get("file", "")
                    ),
                })
            except json.JSONDecodeError:
                continue
        return findings

    def _parse_gitleaks(self, report_path: str) -> list[dict]:
        """Parse gitleaks JSON report file into normalised finding dicts."""
        try:
            with open(report_path) as f:
                data = json.load(f)
            return [
                {
                    "tool": "gitleaks",
                    "detector": item.get("RuleID", "unknown"),
                    "secret": item.get("Secret", ""),
                    "verified": False,
                    "file": item.get("File", ""),
                }
                for item in (data or [])
            ]
        except (json.JSONDecodeError, FileNotFoundError, OSError):
            return []

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Return findings with duplicate secret values removed (first occurrence wins)."""
        seen: set[str] = set()
        unique = []
        for f in findings:
            key = f.get("secret", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
```

- [ ] **Step 4.4: Run the tests to verify they pass**

```
pytest tests/test_info_gathering_wstg_info05.py::TestJsSecretScanner -v
```

Expected: all 7 tests PASS.

- [ ] **Step 4.5: Run the full new test file to confirm nothing regressed**

```
pytest tests/test_info_gathering_wstg_info05.py -v
```

Expected: all tests PASS.

- [ ] **Step 4.6: Commit**

```bash
git add workers/info_gathering/tools/js_secret_scanner.py tests/test_info_gathering_wstg_info05.py
git commit -m "feat(info-gathering): add JsSecretScanner for WSTG-INFO-05 JS secret detection"
```

---

## Task 5: Wire Tools into pipeline.py and concurrency.py

**Files:**
- Modify: `workers/info_gathering/pipeline.py`
- Modify: `workers/info_gathering/concurrency.py`

- [ ] **Step 5.1: Add TOOL_WEIGHTS entries in concurrency.py**

In `workers/info_gathering/concurrency.py`, add three entries to `TOOL_WEIGHTS` after the `"MetadataExtractor": "LIGHT"` line (line 33):

```python
    "MetadataExtractor": "LIGHT",
    "JsSecretScanner": "HEAVY",
    "SourceMapProber": "LIGHT",
    "RedirectBodyInspector": "LIGHT",
```

- [ ] **Step 5.2: Update pipeline.py — imports**

In `workers/info_gathering/pipeline.py`, add three imports after the `from .tools.comment_harvester import CommentHarvester` line:

```python
from .tools.js_secret_scanner import JsSecretScanner
from .tools.redirect_body_inspector import RedirectBodyInspector
from .tools.source_map_prober import SourceMapProber
```

- [ ] **Step 5.3: Update pipeline.py — Stage 5 tool list**

In `STAGES`, change the `review_comments` entry from:

```python
    Stage(name="review_comments", section_id="4.1.5", tools=[CommentHarvester, MetadataExtractor]),
```

to:

```python
    Stage(name="review_comments", section_id="4.1.5", tools=[
        CommentHarvester, MetadataExtractor,
        JsSecretScanner, SourceMapProber, RedirectBodyInspector,
    ]),
```

- [ ] **Step 5.4: Update pipeline.py — split Stage 7**

In `STAGES`, change the `map_execution_paths` entry from:

```python
    Stage(name="map_execution_paths", section_id="4.1.7", tools=[Katana, Hakrawler]),
```

to:

```python
    Stage(name="map_execution_paths", section_id="4.1.7", tools=[Katana, Hakrawler]),
    Stage(name="review_comments_deep", section_id="4.1.5", tools=[
        CommentHarvester, MetadataExtractor,
        JsSecretScanner, SourceMapProber, RedirectBodyInspector,
    ]),
```

`STAGE_INDEX` is rebuilt automatically from `STAGES` — no manual update needed.

- [ ] **Step 5.5: Verify the pipeline module imports cleanly**

```
python -c "from workers.info_gathering.pipeline import STAGES, STAGE_INDEX; print([s.name for s in STAGES])"
```

Expected output (11 stages):

```
['search_engine_recon', 'web_server_fingerprint', 'web_server_metafiles', 'enumerate_applications', 'review_comments', 'identify_entry_points', 'map_execution_paths', 'review_comments_deep', 'fingerprint_framework', 'map_architecture', 'map_application']
```

- [ ] **Step 5.6: Run the full test suite to verify no regressions**

```
pytest tests/ -v --tb=short
```

Expected: all existing tests PASS; all new WSTG-INFO-05 tests PASS.

- [ ] **Step 5.7: Commit**

```bash
git add workers/info_gathering/pipeline.py workers/info_gathering/concurrency.py
git commit -m "feat(info-gathering): wire Stage 5 leakage tools into pipeline; add review_comments_deep after Stage 7"
```

---

## Task 6: Install trufflehog and gitleaks in the Dockerfile

**Files:**
- Modify: `docker/Dockerfile.info_gathering`

- [ ] **Step 6.1: Add installation steps to docker/Dockerfile.info_gathering**

In `docker/Dockerfile.info_gathering`, add the following block after the last `go install` line (currently `RUN go install -v github.com/projectdiscovery/tlsx/...`) and before the `# Stage 2` comment:

```dockerfile
# WSTG-INFO-05 secret scanning tools
RUN go install github.com/gitleaks/gitleaks/v8@latest
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin
```

The full relevant section of the Dockerfile will look like:

```dockerfile
# Stage 2 (WSTG-INFO-02) tooling
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
    && mv /root/go/bin/tlsx /usr/local/bin/tlsx

# WSTG-INFO-05 secret scanning tools
RUN go install github.com/gitleaks/gitleaks/v8@latest
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# Python tools
RUN pip install --no-cache-dir paramspider || true
```

- [ ] **Step 6.2: Verify the Dockerfile builds (runs the info_gathering service only)**

```bash
docker compose build info_gathering
```

Expected: build succeeds with no errors. Verify tools are present:

```bash
docker compose run --rm info_gathering trufflehog --version
docker compose run --rm info_gathering gitleaks version
```

Expected: version strings printed for both tools.

- [ ] **Step 6.3: Commit**

```bash
git add docker/Dockerfile.info_gathering
git commit -m "chore(docker): install trufflehog and gitleaks in info_gathering image"
```
