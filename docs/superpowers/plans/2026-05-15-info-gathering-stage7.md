# Info Gathering Stage 7 — Map Execution Paths Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite Stage 7 (`map_execution_paths`, WSTG-INFO-07) as a fully pipeline-aware stage: fix Katana and Hakrawler to use `host`/`asset_id`/`scope_manager`/`headers`/`rate_limiter`/`intensity`, add a `websocket` asset type fed from Stage 6 into Katana as crawl seeds, and add an in-process `ExecutionPathAnalyzer` post-gather hook that categorizes discovered URLs and writes a single summary Observation.

**Architecture:** Two crawler tools (Katana, Hakrawler) run via `asyncio.gather` and each return a `CrawlResult` dataclass. After the gather, a post-stage hook in `pipeline.run()` calls `ExecutionPathAnalyzer.write_summary()` with the in-memory results — no extra DB round-trip. WebSocket seeds are fetched from the DB before the stage runs and forwarded through `_run_stage` into `tool.execute(**kwargs)`. This mirrors the Stage 2 `FingerprintAggregator` pattern exactly.

**Tech Stack:** Python 3.11+, asyncio, aiosqlite (tests), SQLAlchemy async, pytest-anyio, `unittest.mock` (AsyncMock, patch), Katana CLI, Hakrawler CLI.

**Spec:** `docs/superpowers/specs/2026-05-15-info-gathering-stage7-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `shared/lib_webbh/database.py` | Add `"websocket"`, `"api_endpoint"` to `ASSET_TYPES` |
| Modify | `workers/info_gathering/tools/url_classifier.py` | Add `websocket` and `api_endpoint` URL classifications |
| Modify | `workers/info_gathering/tools/form_mapper.py` | Remove `[:20]` URL cap |
| Create | `workers/info_gathering/tools/execution_path_analyzer.py` | `CrawlResult` dataclass + `ExecutionPathAnalyzer` class |
| Modify | `workers/info_gathering/tools/katana.py` | Full rewrite — pipeline-aware, WS seeds, intensity, returns `CrawlResult` |
| Modify | `workers/info_gathering/tools/hakrawler.py` | Full rewrite — pipeline-aware, intensity, returns `CrawlResult` |
| Modify | `workers/info_gathering/pipeline.py` | Add `_fetch_ws_seeds`, Stage 7 pre/post hooks, `ws_seeds` forwarding through `_run_stage` |
| Create | `tests/test_info_gathering_stage7.py` | Unit tests for all Stage 7 components |
| Create | `tests/test_info_gathering_stage7_integration.py` | End-to-end integration tests |

---

## Task 1: Add `websocket` and `api_endpoint` to asset types and URL classifier

**Files:**
- Modify: `shared/lib_webbh/database.py` (around line 105)
- Modify: `workers/info_gathering/tools/url_classifier.py`
- Create: `tests/test_info_gathering_stage7.py`

- [ ] **Step 1: Create the test file with url_classifier tests**

Create `tests/test_info_gathering_stage7.py`:

```python
"""Unit tests for Stage 7 — Map Execution Paths (WSTG-INFO-07)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.tools.url_classifier import classify_url


# ---------------------------------------------------------------------------
# url_classifier additions
# ---------------------------------------------------------------------------

def test_url_classifier_ws_prefix_returns_websocket():
    assert classify_url("ws://example.com/socket") == "websocket"


def test_url_classifier_wss_prefix_returns_websocket():
    assert classify_url("wss://example.com/ws") == "websocket"


def test_url_classifier_api_v1_path_returns_api_endpoint():
    assert classify_url("https://example.com/api/v1/users") == "api_endpoint"


def test_url_classifier_graphql_returns_api_endpoint():
    assert classify_url("https://example.com/graphql") == "api_endpoint"


def test_url_classifier_rest_path_returns_api_endpoint():
    assert classify_url("https://example.com/rest/items") == "api_endpoint"


def test_url_classifier_ws_check_runs_before_path_rules():
    # A ws:// URL with /api/ in the path should still be websocket, not api_endpoint
    assert classify_url("wss://example.com/api/ws") == "websocket"
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
pytest tests/test_info_gathering_stage7.py::test_url_classifier_ws_prefix_returns_websocket tests/test_info_gathering_stage7.py::test_url_classifier_wss_prefix_returns_websocket tests/test_info_gathering_stage7.py::test_url_classifier_api_v1_path_returns_api_endpoint -v
```

Expected: FAIL — `classify_url("ws://...")` returns `"undetermined"`, not `"websocket"`.

- [ ] **Step 3: Add `websocket` and `api_endpoint` to `ASSET_TYPES` in `database.py`**

In `shared/lib_webbh/database.py`, find the `ASSET_TYPES` tuple (line ~105) and add two new entries:

```python
ASSET_TYPES = (
    "domain",          # Base / root domains
    "ip",              # IP addresses
    "subdomain",       # Subdomains discovered via enumeration
    "sensitive_file",  # Exposed files: .env, .sql, .bak, configs, backups, docs
    "directory",       # Interesting directory paths, admin panels, index-of pages
    "error",           # Error pages leaking stack traces, DB info, debug output
    "form",            # Pages with form fields / submit functionality
    "upload",          # Pages with file upload functionality
    "websocket",       # ws:// / wss:// endpoints
    "api_endpoint",    # REST / GraphQL / RPC paths
    "deadend",         # Low-value pages not worth further exploration
    "undetermined",    # Doesn't fit other categories; needs manual triage
)
```

- [ ] **Step 4: Update `url_classifier.py` with websocket and api_endpoint rules**

Replace the entire contents of `workers/info_gathering/tools/url_classifier.py`:

```python
# workers/info_gathering/tools/url_classifier.py
"""Classify discovered URLs into canonical asset types.

Maps URL characteristics (scheme, extension, path keywords) to the asset
types defined in lib_webbh.database.ASSET_TYPES.
"""

from urllib.parse import urlparse

# Extensions that indicate sensitive / leaked files
_SENSITIVE_EXTENSIONS = frozenset({
    ".env", ".sql", ".bak", ".old", ".backup", ".dump",
    ".conf", ".cfg", ".ini", ".yml", ".yaml", ".toml", ".properties",
    ".key", ".pem", ".p12", ".pfx", ".jks",
    ".log", ".tar", ".gz", ".zip", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
    ".xml", ".json", ".wsdl",
})

# Path fragments that indicate directory listings / admin panels
_DIRECTORY_KEYWORDS = frozenset({
    "/admin", "/administrator", "/cpanel", "/wp-admin",
    "/dashboard", "/manage", "/control",
    "index+of", "index%20of", "parent+directory",
    "/.git/", "/.svn/", "/.env",
    "/wp-content/uploads/",
})

# Path fragments that indicate error / debug pages
_ERROR_KEYWORDS = frozenset({
    "error", "500", "404", "traceback", "stack-trace", "stacktrace",
    "debug", "exception",
})

# Path fragments that indicate API endpoints
_API_PATTERNS = frozenset({
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc",
})

# Dork category → asset type mapping
DORK_CATEGORY_MAP: dict[str, str] = {
    "exposed_files": "sensitive_file",
    "backup_files": "sensitive_file",
    "config_leaks": "sensitive_file",
    "admin_panels": "directory",
    "sensitive_dirs": "directory",
    "error_pages": "error",
    "login_pages": "undetermined",
    "api_endpoints": "api_endpoint",
}


def classify_url(url: str) -> str:
    """Classify a URL into a canonical asset type based on its characteristics.

    Returns one of: websocket, api_endpoint, sensitive_file, directory,
    error, undetermined.
    Does NOT return domain/ip/subdomain/form/upload — those are set by
    the tools that have richer context (DNS enumeration, form detection, etc.).
    """
    # WebSocket scheme — checked first, before any path rules
    if url.startswith(("ws://", "wss://")):
        return "websocket"

    parsed = urlparse(url)
    path = parsed.path.lower()

    # Check extension for sensitive files
    for ext in _SENSITIVE_EXTENSIONS:
        if path.endswith(ext):
            return "sensitive_file"

    # Check path for directory listings / admin panels
    url_lower = url.lower()
    for kw in _DIRECTORY_KEYWORDS:
        if kw in url_lower:
            return "directory"

    # Check for API endpoint patterns
    for pattern in _API_PATTERNS:
        if pattern in url_lower:
            return "api_endpoint"

    # Check for error pages (less reliable from URL alone)
    last_segment = path.rsplit("/", 1)[-1].lower()
    for kw in _ERROR_KEYWORDS:
        if kw in last_segment:
            return "error"

    return "undetermined"
```

- [ ] **Step 5: Run the url_classifier tests to verify they pass**

```bash
pytest tests/test_info_gathering_stage7.py -k "url_classifier" -v
```

Expected: 6 PASS.

- [ ] **Step 6: Run the full existing test suite to check for regressions**

```bash
pytest tests/ -v --tb=short -q
```

Expected: All previously passing tests still pass. (The only change to `ASSET_TYPES` is additive; the classifier change adds two new return values but does not alter existing return values for non-WS, non-API URLs.)

- [ ] **Step 7: Commit**

```bash
git add shared/lib_webbh/database.py workers/info_gathering/tools/url_classifier.py tests/test_info_gathering_stage7.py
git commit -m "feat(info-gathering): add websocket and api_endpoint asset types; update url_classifier"
```

---

## Task 2: Remove URL caps globally

**Files:**
- Modify: `workers/info_gathering/tools/form_mapper.py`
- Modify: `tests/test_info_gathering_stage7.py`

- [ ] **Step 1: Add the FormMapper cap-removal test to `tests/test_info_gathering_stage7.py`**

Append to the test file:

```python
# ---------------------------------------------------------------------------
# FormMapper URL cap removal
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_form_mapper_processes_more_than_20_urls():
    """FormMapper must not silently cap at 20 URLs."""
    from workers.info_gathering.tools.form_mapper import FormMapper

    tool = FormMapper()

    # 25 pre-existing URL assets in the DB mock
    url_assets = [f"https://example.com/page{i}" for i in range(25)]

    mock_forms = [{"action": "https://example.com/submit", "method": "POST", "inputs": ["email"]}]

    saved_urls: list[str] = []

    async def mock_save_asset(target_id, asset_type, url, source, **kwargs):
        saved_urls.append(url)
        return len(saved_urls)

    async def mock_extract_forms(url):
        return mock_forms

    # Patch DB query to return 25 URL assets
    from contextlib import asynccontextmanager
    from unittest.mock import MagicMock

    mock_result = MagicMock()
    mock_result.all.return_value = [(u,) for u in url_assets]
    mock_execute = AsyncMock(return_value=mock_result)
    mock_session = MagicMock()
    mock_session.execute = mock_execute
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    @asynccontextmanager
    async def mock_get_session():
        yield mock_session

    target = MagicMock(base_domain="example.com")

    with patch("workers.info_gathering.tools.form_mapper.get_session", mock_get_session), \
         patch.object(tool, "save_asset", side_effect=mock_save_asset), \
         patch.object(tool, "_extract_forms", side_effect=mock_extract_forms), \
         patch.object(tool, "save_observation", new=AsyncMock()):
        await tool.execute(target_id=1, target=target)

    # Should have processed all 26 URLs (25 from DB + 1 base domain prepended)
    assert len(saved_urls) > 20, (
        f"FormMapper capped at {len(saved_urls)} URLs — cap was not removed"
    )
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/test_info_gathering_stage7.py::test_form_mapper_processes_more_than_20_urls -v
```

Expected: FAIL — FormMapper only processes 20 URLs due to `urls[:20]` cap.

- [ ] **Step 3: Remove the `[:20]` cap in `form_mapper.py`**

In `workers/info_gathering/tools/form_mapper.py`, change:

```python
        for url in urls[:20]:  # Limit to 20 pages
```

to:

```python
        for url in urls:
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/test_info_gathering_stage7.py::test_form_mapper_processes_more_than_20_urls -v
```

Expected: PASS.

- [ ] **Step 5: Grep for any other URL caps in the codebase**

```bash
grep -rn "\[:\d\+\]" workers/ --include="*.py"
```

If any other `[:N]` slices appear on URL/asset lists, remove those caps too and update the commit below.

- [ ] **Step 6: Commit**

```bash
git add workers/info_gathering/tools/form_mapper.py tests/test_info_gathering_stage7.py
git commit -m "fix(info-gathering): remove URL caps from FormMapper and any other URL-list slices"
```

---

## Task 3: Create `CrawlResult` dataclass and `ExecutionPathAnalyzer` scaffold

**Files:**
- Create: `workers/info_gathering/tools/execution_path_analyzer.py`

No test needed at this step — tests for the full `ExecutionPathAnalyzer` come in Task 6. This task just establishes the types and stubs that Tasks 4, 5, and 6 all import.

- [ ] **Step 1: Create `execution_path_analyzer.py` with the dataclass and class stub**

Create `workers/info_gathering/tools/execution_path_analyzer.py`:

```python
# workers/info_gathering/tools/execution_path_analyzer.py
"""Post-crawl execution path analyzer for Stage 7 (WSTG-INFO-07).

Consumes CrawlResult objects produced by Katana and Hakrawler, categorizes
all discovered URLs into execution path buckets, and writes a single summary
Observation to the database.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from lib_webbh import get_session, setup_logger
from lib_webbh.database import Observation
from workers.info_gathering.base_tool import InfoGatheringTool

logger = setup_logger("info-gathering-stage7")


@dataclass
class CrawlResult:
    """Structured output from a single crawler tool (Katana or Hakrawler)."""
    tool: str                          # "katana" | "hakrawler"
    urls: list[str] = field(default_factory=list)      # discovered non-WS URLs
    ws_urls: list[str] = field(default_factory=list)   # ws:// / wss:// URLs
    error: str | None = None           # set if tool failed; analyzer marks summary partial


# ---------------------------------------------------------------------------
# Categorization rules — priority order, first match wins
# ---------------------------------------------------------------------------
_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("websocket",     ("ws://", "wss://")),
    ("api_endpoint",  ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc")),
    ("auth_flow",     ("/login", "/logout", "/auth", "/oauth", "/signin", "/signup",
                       "/register", "/password", "/forgot", "/reset", "/sso", "/saml")),
    ("admin_panel",   ("/admin", "/administrator", "/management", "/manage",
                       "/control", "/cms", "/wp-admin", "/cpanel")),
    ("file_download", (".pdf", ".zip", ".csv", ".xlsx", ".docx", ".tar", ".gz")),
    ("static_asset",  (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ttf", ".ico")),
    ("error_page",    ("/error", "/404", "/500", "traceback", "exception")),
]

_DEPTH_MAP: dict[str, int] = {"low": 2, "medium": 3, "high": 5}


def _categorize(url: str) -> str:
    """Return the first matching category for a URL, or 'other'."""
    url_lower = url.lower()
    for category, patterns in _CATEGORIES:
        if any(p in url_lower for p in patterns):
            return category
    return "other"


class ExecutionPathAnalyzer(InfoGatheringTool):
    """Post-crawl in-process path analyzer for Stage 7.

    Invoked by pipeline.run() after asyncio.gather completes for the
    map_execution_paths stage. Not listed in stage.tools — it runs as a
    post-gather hook, mirroring FingerprintAggregator in Stage 2.
    """

    def __init__(self, asset_id: int, target_id: int):
        self.asset_id = asset_id
        self.target_id = target_id
        self.log = logger.bind(target_id=target_id, asset_id=asset_id)

    async def execute(self, target_id: int, **kwargs) -> None:
        # Invoked via write_summary(), not execute().
        pass

    async def write_summary(
        self, crawl_results: list[CrawlResult], intensity: str = "low",
    ) -> int | None:
        """Categorize all crawled URLs and write a single summary Observation.

        Returns the Observation.id, or None if no results were provided.
        """
        if not crawl_results:
            return None

        depth = _DEPTH_MAP.get(intensity, 2)
        all_urls: list[str] = []
        ws_seeds_used: list[str] = []
        tool_breakdown: dict[str, dict] = {}
        any_error = False

        for result in crawl_results:
            errored = result.error is not None
            if errored:
                any_error = True
            tool_breakdown[result.tool] = {
                "total": len(result.urls) + len(result.ws_urls),
                "errored": errored,
            }
            all_urls.extend(result.urls)
            all_urls.extend(result.ws_urls)
            ws_seeds_used.extend(result.ws_urls)

        # Build category map (all keys present even if empty)
        categories: dict[str, list[str]] = {cat: [] for cat, _ in _CATEGORIES}
        categories["other"] = []
        for url in all_urls:
            categories[_categorize(url)].append(url)

        tech_stack: dict = {
            "_probe": "execution_paths",
            "intensity": intensity,
            "depth": depth,
            "total_paths": len(all_urls),
            "ws_seeds_used": ws_seeds_used,
            "categories": categories,
            "tool_breakdown": tool_breakdown,
        }
        if any_error:
            tech_stack["partial"] = True

        async with get_session() as session:
            obs = Observation(
                asset_id=self.asset_id,
                tech_stack=tech_stack,
            )
            session.add(obs)
            await session.commit()
            await session.refresh(obs)
            self.log.info("Stage 7 summary observation written", extra={"obs_id": obs.id})
            return obs.id
```

- [ ] **Step 2: Verify the file imports cleanly (no syntax errors)**

```bash
python -c "from workers.info_gathering.tools.execution_path_analyzer import CrawlResult, ExecutionPathAnalyzer; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add workers/info_gathering/tools/execution_path_analyzer.py
git commit -m "feat(info-gathering): add CrawlResult dataclass and ExecutionPathAnalyzer scaffold"
```

---

## Task 4: Rewrite `Katana`

**Files:**
- Modify: `workers/info_gathering/tools/katana.py`
- Modify: `tests/test_info_gathering_stage7.py`

- [ ] **Step 1: Add Katana unit tests to `tests/test_info_gathering_stage7.py`**

Append to the test file:

```python
# ---------------------------------------------------------------------------
# Katana unit tests
# ---------------------------------------------------------------------------

from workers.info_gathering.tools.katana import Katana
from workers.info_gathering.tools.execution_path_analyzer import CrawlResult


@pytest.mark.anyio
async def test_katana_uses_host_not_base_domain():
    """Katana must crawl `host` kwarg, not target.base_domain."""
    tool = Katana()
    target = MagicMock(base_domain="base.com")
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        result = await tool.execute(
            target_id=1,
            target=target,
            host="api.base.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert captured_cmds, "run_subprocess was never called"
    all_args = " ".join(captured_cmds[0])
    assert "api.base.com" in all_args
    assert "https://base.com" not in all_args


@pytest.mark.anyio
async def test_katana_intensity_low_sets_depth_2():
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            intensity="low",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    assert "-d" in cmd
    assert cmd[cmd.index("-d") + 1] == "2"


@pytest.mark.anyio
async def test_katana_intensity_high_sets_depth_5():
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            intensity="high",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    assert cmd[cmd.index("-d") + 1] == "5"


@pytest.mark.anyio
async def test_katana_feeds_ws_seeds_as_additional_urls():
    """WS seed URLs must appear as additional -u args in the Katana command."""
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            ws_seeds=["wss://example.com/ws", "ws://example.com/events"],
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    # Both WS seeds must appear after -u flags
    assert "wss://example.com/ws" in cmd
    assert "ws://example.com/events" in cmd


@pytest.mark.anyio
async def test_katana_scope_check_filters_out_of_scope_urls():
    """URLs that fail scope_check must not be saved as assets."""
    tool = Katana()

    katana_output = '{"url": "https://evil.com/page"}\n{"url": "https://example.com/safe"}'

    scope_manager = MagicMock(_in_scope_patterns={"example.com"})
    scope_manager.classify = MagicMock(side_effect=lambda url: MagicMock(
        classification="in-scope" if "example.com" in url else "out-of-scope"
    ))

    saved: list[str] = []

    async def mock_save(target_id, asset_type, url, source, **kwargs):
        saved.append(url)
        return 1

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=katana_output)), \
         patch.object(tool, "save_asset", side_effect=mock_save):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=scope_manager,
        )

    assert "https://evil.com/page" not in saved
    assert "https://example.com/safe" in saved


@pytest.mark.anyio
async def test_katana_saves_ws_url_as_websocket_asset_type():
    """A wss:// URL discovered during crawl is saved as asset_type='websocket'."""
    tool = Katana()

    katana_output = '{"url": "wss://example.com/ws"}'

    saved_types: list[tuple[str, str]] = []

    async def mock_save(target_id, asset_type, url, source, **kwargs):
        saved_types.append((asset_type, url))
        return 1

    scope_manager = MagicMock(_in_scope_patterns=set())

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=katana_output)), \
         patch.object(tool, "save_asset", side_effect=mock_save):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=scope_manager,
        )

    assert ("websocket", "wss://example.com/ws") in saved_types


@pytest.mark.anyio
async def test_katana_returns_crawl_result():
    """Katana.execute must return a CrawlResult instance."""
    tool = Katana()

    katana_output = '{"url": "https://example.com/page"}\n{"url": "wss://example.com/ws"}'

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=katana_output)), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.tool == "katana"
    assert result.error is None
    assert "https://example.com/page" in result.urls
    assert "wss://example.com/ws" in result.ws_urls


@pytest.mark.anyio
async def test_katana_headers_forwarded_as_H_flags():
    """Custom headers must appear as -H 'Key: Value' in the Katana command."""
    tool = Katana()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            headers={"Cookie": "session=abc123", "X-Custom": "value"},
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    cmd_str = " ".join(cmd)
    assert "Cookie: session=abc123" in cmd_str
    assert "X-Custom: value" in cmd_str


@pytest.mark.anyio
async def test_katana_returns_crawl_result_with_error_on_subprocess_failure():
    """On subprocess failure, Katana returns CrawlResult with error set."""
    tool = Katana()

    with patch.object(tool, "run_subprocess", side_effect=TimeoutError("timed out")):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.error is not None
    assert "timed out" in result.error
    assert result.urls == []
```

- [ ] **Step 2: Run the Katana tests to verify they fail**

```bash
pytest tests/test_info_gathering_stage7.py -k "katana" -v
```

Expected: All FAIL — current `Katana.execute` returns `None`, not a `CrawlResult`.

- [ ] **Step 3: Rewrite `workers/info_gathering/tools/katana.py`**

Replace the entire file:

```python
# workers/info_gathering/tools/katana.py
"""Katana wrapper — web crawling and execution path discovery (WSTG-INFO-07)."""

import json

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.execution_path_analyzer import CrawlResult
from workers.info_gathering.tools.url_classifier import classify_url

_DEPTH_MAP: dict[str, int] = {"low": 2, "medium": 3, "high": 5}


class Katana(InfoGatheringTool):
    """Web crawler — JS-aware, form-following, scope-enforced."""

    async def execute(self, target_id: int, **kwargs) -> CrawlResult:
        host: str | None = kwargs.get("host")
        target = kwargs.get("target")
        if not host and target:
            host = target.base_domain
        if not host:
            return CrawlResult(tool="katana", error="no host provided")

        scope_manager = kwargs.get("scope_manager")
        headers: dict = kwargs.get("headers") or {}
        rate_limiter = kwargs.get("rate_limiter")
        intensity: str = kwargs.get("intensity") or "low"
        ws_seeds: list[str] = kwargs.get("ws_seeds") or []

        depth = _DEPTH_MAP.get(intensity, 2)

        # Seed URLs: primary host + any WebSocket endpoints from Stage 6
        seed_urls = [f"https://{host}"] + list(ws_seeds)

        cmd = [
            "katana",
            "-j",       # JSON output
            "-silent",  # suppress progress
            "-jc",      # enable JS file endpoint parsing
            "-headless",        # full headless JS rendering
            "-passive",         # passive JS execution
            "-form-extraction", # extract and follow forms
            "-d", str(depth),
        ]
        for url in seed_urls:
            cmd += ["-u", url]
        for key, value in headers.items():
            cmd += ["-H", f"{key}: {value}"]

        try:
            stdout = await self.run_subprocess(cmd, timeout=900, rate_limiter=rate_limiter)
        except Exception as exc:
            return CrawlResult(tool="katana", error=str(exc))

        discovered: list[str] = []
        ws_found: list[str] = []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            url = ""
            try:
                data = json.loads(line)
                url = data.get("url", "")
            except json.JSONDecodeError:
                if line.startswith(("http", "ws")):
                    url = line

            if not url:
                continue

            if scope_manager and not await self.scope_check(target_id, url, scope_manager):
                continue

            asset_type = classify_url(url)
            await self.save_asset(target_id, asset_type, url, "katana",
                                  scope_manager=scope_manager)

            if asset_type == "websocket":
                ws_found.append(url)
            else:
                discovered.append(url)

        return CrawlResult(tool="katana", urls=discovered, ws_urls=ws_found)
```

- [ ] **Step 4: Run the Katana tests to verify they pass**

```bash
pytest tests/test_info_gathering_stage7.py -k "katana" -v
```

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/info_gathering/tools/katana.py tests/test_info_gathering_stage7.py
git commit -m "feat(info-gathering): rewrite Katana — pipeline-aware, WS seeds, intensity, CrawlResult"
```

---

## Task 5: Rewrite `Hakrawler`

**Files:**
- Modify: `workers/info_gathering/tools/hakrawler.py`
- Modify: `tests/test_info_gathering_stage7.py`

- [ ] **Step 1: Add Hakrawler unit tests to `tests/test_info_gathering_stage7.py`**

Append to the test file:

```python
# ---------------------------------------------------------------------------
# Hakrawler unit tests
# ---------------------------------------------------------------------------

from workers.info_gathering.tools.hakrawler import Hakrawler


@pytest.mark.anyio
async def test_hakrawler_uses_host_not_base_domain():
    """Hakrawler must crawl `host` kwarg, not target.base_domain."""
    tool = Hakrawler()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="base.com"),
            host="api.base.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert captured_cmds, "run_subprocess was never called"
    all_args = " ".join(captured_cmds[0])
    assert "api.base.com" in all_args
    assert "https://base.com" not in all_args


@pytest.mark.anyio
async def test_hakrawler_intensity_medium_sets_depth_3():
    tool = Hakrawler()
    captured_cmds: list[list[str]] = []

    async def mock_subprocess(cmd, **kwargs):
        captured_cmds.append(cmd)
        return ""

    with patch.object(tool, "run_subprocess", side_effect=mock_subprocess), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            intensity="medium",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    cmd = captured_cmds[0]
    assert "-depth" in cmd
    assert cmd[cmd.index("-depth") + 1] == "3"


@pytest.mark.anyio
async def test_hakrawler_returns_crawl_result():
    """Hakrawler.execute must return a CrawlResult instance."""
    tool = Hakrawler()

    output = "https://example.com/page1\nhttps://example.com/page2\n"

    with patch.object(tool, "run_subprocess", new=AsyncMock(return_value=output)), \
         patch.object(tool, "save_asset", new=AsyncMock(return_value=1)):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.tool == "hakrawler"
    assert result.error is None
    assert "https://example.com/page1" in result.urls


@pytest.mark.anyio
async def test_hakrawler_returns_error_on_subprocess_failure():
    tool = Hakrawler()

    with patch.object(tool, "run_subprocess", side_effect=TimeoutError("timeout")):
        result = await tool.execute(
            target_id=1,
            target=MagicMock(base_domain="example.com"),
            host="example.com",
            scope_manager=MagicMock(_in_scope_patterns=set()),
        )

    assert isinstance(result, CrawlResult)
    assert result.error is not None
    assert result.urls == []
```

- [ ] **Step 2: Run the Hakrawler tests to verify they fail**

```bash
pytest tests/test_info_gathering_stage7.py -k "hakrawler" -v
```

Expected: All FAIL.

- [ ] **Step 3: Rewrite `workers/info_gathering/tools/hakrawler.py`**

Replace the entire file:

```python
# workers/info_gathering/tools/hakrawler.py
"""Hakrawler wrapper — fast HTTP web crawling (WSTG-INFO-07)."""

from workers.info_gathering.base_tool import InfoGatheringTool
from workers.info_gathering.tools.execution_path_analyzer import CrawlResult
from workers.info_gathering.tools.url_classifier import classify_url

_DEPTH_MAP: dict[str, int] = {"low": 2, "medium": 3, "high": 5}


class Hakrawler(InfoGatheringTool):
    """Fast HTTP crawler — scope-enforced, intensity-aware."""

    async def execute(self, target_id: int, **kwargs) -> CrawlResult:
        host: str | None = kwargs.get("host")
        target = kwargs.get("target")
        if not host and target:
            host = target.base_domain
        if not host:
            return CrawlResult(tool="hakrawler", error="no host provided")

        scope_manager = kwargs.get("scope_manager")
        headers: dict = kwargs.get("headers") or {}
        rate_limiter = kwargs.get("rate_limiter")
        intensity: str = kwargs.get("intensity") or "low"

        depth = _DEPTH_MAP.get(intensity, 2)

        cmd = [
            "hakrawler",
            "-url", f"https://{host}",
            "-depth", str(depth),
        ]
        for key, value in headers.items():
            cmd += ["-h", f"{key}: {value}"]

        try:
            stdout = await self.run_subprocess(cmd, timeout=600, rate_limiter=rate_limiter)
        except Exception as exc:
            return CrawlResult(tool="hakrawler", error=str(exc))

        discovered: list[str] = []
        ws_found: list[str] = []

        for line in stdout.strip().splitlines():
            url = line.strip()
            if not url or not url.startswith(("http", "ws")):
                continue

            if scope_manager and not await self.scope_check(target_id, url, scope_manager):
                continue

            asset_type = classify_url(url)
            await self.save_asset(target_id, asset_type, url, "hakrawler",
                                  scope_manager=scope_manager)

            if asset_type == "websocket":
                ws_found.append(url)
            else:
                discovered.append(url)

        return CrawlResult(tool="hakrawler", urls=discovered, ws_urls=ws_found)
```

- [ ] **Step 4: Run the Hakrawler tests to verify they pass**

```bash
pytest tests/test_info_gathering_stage7.py -k "hakrawler" -v
```

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/info_gathering/tools/hakrawler.py tests/test_info_gathering_stage7.py
git commit -m "feat(info-gathering): rewrite Hakrawler — pipeline-aware, intensity, CrawlResult"
```

---

## Task 6: ExecutionPathAnalyzer unit tests

**Files:**
- Modify: `tests/test_info_gathering_stage7.py`

The implementation already exists from Task 3. This task adds the unit tests and verifies the implementation is correct.

- [ ] **Step 1: Add ExecutionPathAnalyzer unit tests to `tests/test_info_gathering_stage7.py`**

Append to the test file:

```python
# ---------------------------------------------------------------------------
# ExecutionPathAnalyzer unit tests
# ---------------------------------------------------------------------------

from contextlib import asynccontextmanager
from workers.info_gathering.tools.execution_path_analyzer import (
    ExecutionPathAnalyzer,
    CrawlResult,
    _categorize,
)


def test_categorize_auth_flow_urls():
    assert _categorize("https://example.com/login") == "auth_flow"
    assert _categorize("https://example.com/oauth/callback") == "auth_flow"
    assert _categorize("https://example.com/signup") == "auth_flow"
    assert _categorize("https://example.com/password/reset") == "auth_flow"


def test_categorize_admin_panel_urls():
    assert _categorize("https://example.com/admin") == "admin_panel"
    assert _categorize("https://example.com/wp-admin/") == "admin_panel"
    assert _categorize("https://example.com/cpanel/dashboard") == "admin_panel"


def test_categorize_api_endpoint_urls():
    assert _categorize("https://example.com/api/v1/users") == "api_endpoint"
    assert _categorize("https://example.com/graphql") == "api_endpoint"
    assert _categorize("https://example.com/rest/items") == "api_endpoint"


def test_categorize_websocket_urls():
    assert _categorize("wss://example.com/ws") == "websocket"
    assert _categorize("ws://example.com/events") == "websocket"


def test_categorize_first_matching_bucket_wins():
    # /api/login could match both api_endpoint and auth_flow;
    # api_endpoint appears earlier in _CATEGORIES so it wins.
    result = _categorize("https://example.com/api/login")
    assert result == "api_endpoint"


def test_categorize_other_for_unknown_urls():
    assert _categorize("https://example.com/about") == "other"
    assert _categorize("https://example.com/products/widget") == "other"


@pytest.mark.anyio
async def test_analyzer_writes_summary_observation_with_correct_asset_id():
    """write_summary must write an Observation linked to asset_id."""
    from lib_webbh.database import Observation
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool
    from lib_webbh.database import Base
    from sqlalchemy import select

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    Session = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def fake_session():
        async with Session() as s:
            yield s

    results = [
        CrawlResult(tool="katana", urls=["https://example.com/page"], ws_urls=[]),
        CrawlResult(tool="hakrawler", urls=["https://example.com/other"], ws_urls=[]),
    ]

    with patch("workers.info_gathering.tools.execution_path_analyzer.get_session", fake_session):
        analyzer = ExecutionPathAnalyzer(asset_id=42, target_id=1)
        obs_id = await analyzer.write_summary(results, intensity="medium")

    assert obs_id is not None

    async with Session() as session:
        obs = (await session.execute(select(Observation).where(Observation.id == obs_id))).scalar_one()
        assert obs.asset_id == 42
        assert obs.tech_stack["_probe"] == "execution_paths"
        assert obs.tech_stack["intensity"] == "medium"
        assert obs.tech_stack["depth"] == 3
        assert obs.tech_stack["total_paths"] == 2

    await engine.dispose()


@pytest.mark.anyio
async def test_analyzer_partial_true_when_both_crawlers_error():
    from lib_webbh.database import Base, Observation
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool
    from sqlalchemy import select

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def fake_session():
        async with Session() as s:
            yield s

    results = [
        CrawlResult(tool="katana", error="timed out"),
        CrawlResult(tool="hakrawler", error="connection refused"),
    ]

    with patch("workers.info_gathering.tools.execution_path_analyzer.get_session", fake_session):
        analyzer = ExecutionPathAnalyzer(asset_id=7, target_id=1)
        obs_id = await analyzer.write_summary(results, intensity="low")

    async with Session() as session:
        obs = (await session.execute(select(Observation).where(Observation.id == obs_id))).scalar_one()
        assert obs.tech_stack.get("partial") is True
        assert obs.tech_stack["total_paths"] == 0

    await engine.dispose()


@pytest.mark.anyio
async def test_analyzer_partial_true_when_one_crawler_errors():
    from lib_webbh.database import Base, Observation
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool
    from sqlalchemy import select

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def fake_session():
        async with Session() as s:
            yield s

    results = [
        CrawlResult(tool="katana", urls=["https://example.com/page"], ws_urls=[]),
        CrawlResult(tool="hakrawler", error="timeout"),
    ]

    with patch("workers.info_gathering.tools.execution_path_analyzer.get_session", fake_session):
        analyzer = ExecutionPathAnalyzer(asset_id=7, target_id=1)
        obs_id = await analyzer.write_summary(results, intensity="low")

    async with Session() as session:
        obs = (await session.execute(select(Observation).where(Observation.id == obs_id))).scalar_one()
        assert obs.tech_stack.get("partial") is True
        assert obs.tech_stack["total_paths"] == 1

    await engine.dispose()


@pytest.mark.anyio
async def test_analyzer_tool_breakdown_reflects_per_tool_counts():
    from lib_webbh.database import Base, Observation
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool
    from sqlalchemy import select

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def fake_session():
        async with Session() as s:
            yield s

    results = [
        CrawlResult(tool="katana", urls=["u1", "u2", "u3"], ws_urls=["wss://x.com/ws"]),
        CrawlResult(tool="hakrawler", urls=["u4", "u5"], ws_urls=[]),
    ]

    with patch("workers.info_gathering.tools.execution_path_analyzer.get_session", fake_session):
        analyzer = ExecutionPathAnalyzer(asset_id=1, target_id=1)
        obs_id = await analyzer.write_summary(results, intensity="low")

    async with Session() as session:
        obs = (await session.execute(select(Observation).where(Observation.id == obs_id))).scalar_one()
        breakdown = obs.tech_stack["tool_breakdown"]
        assert breakdown["katana"]["total"] == 4   # 3 urls + 1 ws_url
        assert breakdown["hakrawler"]["total"] == 2
        assert breakdown["katana"]["errored"] is False
        assert breakdown["hakrawler"]["errored"] is False

    await engine.dispose()
```

- [ ] **Step 2: Run the ExecutionPathAnalyzer tests to verify they pass**

```bash
pytest tests/test_info_gathering_stage7.py -k "analyzer or categorize" -v
```

Expected: All PASS (implementation already exists from Task 3).

- [ ] **Step 3: Run the full Stage 7 unit test suite**

```bash
pytest tests/test_info_gathering_stage7.py -v
```

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_info_gathering_stage7.py
git commit -m "test(info-gathering): add Stage 7 unit tests for analyzer, Katana, Hakrawler, url_classifier"
```

---

## Task 7: Wire Stage 7 hooks into `pipeline.py`

**Files:**
- Modify: `workers/info_gathering/pipeline.py`
- Modify: `tests/test_info_gathering_stage7.py`

- [ ] **Step 1: Add pipeline unit tests for Stage 7 hooks to `tests/test_info_gathering_stage7.py`**

Append to the test file:

```python
# ---------------------------------------------------------------------------
# Pipeline Stage 7 hook unit tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_pipeline_fetch_ws_seeds_returns_websocket_assets():
    """_fetch_ws_seeds must query DB for asset_type='websocket' under target_id."""
    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=5, container_name="info_gathering")

    from lib_webbh.database import Base, Asset, Target
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool
    from contextlib import asynccontextmanager

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as sess:
        t = Target(id=5, company_name="Test", base_domain="example.com")
        sess.add(t)
        await sess.flush()
        ws1 = Asset(target_id=5, asset_type="websocket", asset_value="wss://example.com/ws")
        ws2 = Asset(target_id=5, asset_type="websocket", asset_value="ws://example.com/events")
        other = Asset(target_id=5, asset_type="url", asset_value="https://example.com/page")
        sess.add_all([ws1, ws2, other])
        await sess.commit()

    @asynccontextmanager
    async def fake_session():
        async with Session() as s:
            yield s

    with patch("workers.info_gathering.pipeline.get_session", fake_session):
        seeds = await pipeline._fetch_ws_seeds(5)

    assert "wss://example.com/ws" in seeds
    assert "ws://example.com/events" in seeds
    assert "https://example.com/page" not in seeds

    await engine.dispose()
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pytest tests/test_info_gathering_stage7.py::test_pipeline_fetch_ws_seeds_returns_websocket_assets -v
```

Expected: FAIL — `Pipeline` has no `_fetch_ws_seeds` method.

- [ ] **Step 3: Update `workers/info_gathering/pipeline.py`**

**3a.** Add the import for `ExecutionPathAnalyzer` and `CrawlResult` near the existing `FingerprintAggregator` import (around line 66):

Find:
```python
from workers.info_gathering.fingerprint_aggregator import FingerprintAggregator, ProbeResult
```

Replace with:
```python
from workers.info_gathering.fingerprint_aggregator import FingerprintAggregator, ProbeResult
from workers.info_gathering.tools.execution_path_analyzer import ExecutionPathAnalyzer, CrawlResult
```

**3b.** Add the `_STAGE7_SECTION` constant after `_STAGE2_SECTION` (around line 100):

Find:
```python
# WSTG-INFO-02 section id — matched in run() to gate FingerprintAggregator invocation.
_STAGE2_SECTION = "4.1.2"
```

Replace with:
```python
# WSTG-INFO-02 section id — matched in run() to gate FingerprintAggregator invocation.
_STAGE2_SECTION = "4.1.2"
# WSTG-INFO-07 section id — matched in run() to gate ExecutionPathAnalyzer invocation.
_STAGE7_SECTION = "4.1.7"
```

**3c.** Add `_fetch_ws_seeds` method to the `Pipeline` class. Add it after the `_classify_pending_assets` method (after line 361):

```python
    async def _fetch_ws_seeds(self, target_id: int) -> list[str]:
        """Return all websocket asset URLs discovered for target_id so far."""
        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "websocket",
            )
            result = await session.execute(stmt)
            return [row[0] for row in result.all()]
```

**3d.** Update `_run_stage` signature to accept `ws_seeds`. Find:

```python
    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        rate_limiter=None,
        asset_id: int | None = None,
        host: str | None = None,
        intensity: str = "low",
    ) -> list:
```

Replace with:

```python
    async def _run_stage(
        self,
        stage: Stage,
        target,
        scope_manager: ScopeManager,
        headers: dict | None = None,
        rate_limiter=None,
        asset_id: int | None = None,
        host: str | None = None,
        intensity: str = "low",
        ws_seeds: list[str] | None = None,
    ) -> list:
```

**3e.** Inside `_run_stage`, add `ws_seeds` to the `tool.execute` kwargs. Find:

```python
        tasks = [
            tool.execute(
                target_id=self.target_id,
                scope_manager=scope_manager,
                headers=headers,
                container_name=self.container_name,
                rate_limiter=rate_limiter,
                target=target,
                asset_id=asset_id,
                host=host,
                intensity=intensity,
            )
            for tool in tools
        ]
```

Replace with:

```python
        tasks = [
            tool.execute(
                target_id=self.target_id,
                scope_manager=scope_manager,
                headers=headers,
                container_name=self.container_name,
                rate_limiter=rate_limiter,
                target=target,
                asset_id=asset_id,
                host=host,
                intensity=intensity,
                ws_seeds=ws_seeds or [],
            )
            for tool in tools
        ]
```

**3f.** In `run()`, add the Stage 7 pre-fetch and post-gather hook. Find the existing Stage 2 hook block and the `_run_stage` call:

```python
        for stage in stages[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            results = await self._run_stage(
                stage, target, scope_manager=scope_manager,
                headers=headers, rate_limiter=rate_limiter,
                asset_id=asset_id, host=host, intensity=intensity,
            )
```

Replace with:

```python
        for stage in stages[start_index:]:
            self.log.info(f"Starting stage: {stage.name}")
            await self._update_phase(stage.name)

            # Pre-Stage 7: fetch WebSocket seeds discovered by prior stages
            ws_seeds: list[str] = []
            if stage.section_id == _STAGE7_SECTION:
                ws_seeds = await self._fetch_ws_seeds(self.target_id)

            results = await self._run_stage(
                stage, target, scope_manager=scope_manager,
                headers=headers, rate_limiter=rate_limiter,
                asset_id=asset_id, host=host, intensity=intensity,
                ws_seeds=ws_seeds,
            )
```

**3g.** Add the Stage 7 post-gather hook. Find the existing Stage 2 post-gather block:

```python
            stats = self._stats_from_results(results)
            if stage.section_id == _STAGE2_SECTION:
```

And add the Stage 7 block directly after the Stage 2 block ends (after the closing of the `if stage.section_id == _STAGE2_SECTION:` block):

```python
            if stage.section_id == _STAGE7_SECTION:
                analyzer = ExecutionPathAnalyzer(
                    asset_id=asset_id, target_id=self.target_id,
                )
                crawl_results = [r for r in results if isinstance(r, CrawlResult)]
                summary_obs_id = await analyzer.write_summary(
                    crawl_results, intensity=intensity,
                )
                stats["paths_found"] = sum(
                    len(r.urls) + len(r.ws_urls)
                    for r in crawl_results
                    if r.error is None
                )
                stats["summary_written"] = summary_obs_id is not None
```

- [ ] **Step 4: Run the pipeline unit test to verify it passes**

```bash
pytest tests/test_info_gathering_stage7.py::test_pipeline_fetch_ws_seeds_returns_websocket_assets -v
```

Expected: PASS.

- [ ] **Step 5: Run the full Stage 7 unit test suite**

```bash
pytest tests/test_info_gathering_stage7.py -v
```

Expected: All PASS.

- [ ] **Step 6: Run the full test suite to check for regressions**

```bash
pytest tests/ -v --tb=short -q
```

Expected: All previously passing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add workers/info_gathering/pipeline.py tests/test_info_gathering_stage7.py
git commit -m "feat(info-gathering): wire Stage 7 pre/post hooks into pipeline; add _fetch_ws_seeds"
```

---

## Task 8: Integration tests

**Files:**
- Create: `tests/test_info_gathering_stage7_integration.py`

These tests exercise the full Stage 7 path: pipeline pre-fetch → Katana + Hakrawler (subprocess mocked) → ExecutionPathAnalyzer → DB writes → SSE event. They use the same `db_engine` fixture pattern as `test_info_gathering_stage2_integration.py`.

- [ ] **Step 1: Create `tests/test_info_gathering_stage7_integration.py`**

```python
"""Stage 7 (map_execution_paths) integration tests.

Exercises the full path: pipeline _fetch_ws_seeds → asyncio.gather(Katana, Hakrawler)
→ ExecutionPathAnalyzer.write_summary → DB writes → SSE STAGE_COMPLETE event.

Uses aiosqlite for DB (NullPool, WAL), subprocess mocked via patch.object on
InfoGatheringTool.run_subprocess.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from lib_webbh.database import Asset, Base, Observation, Target, JobState
from workers.info_gathering.base_tool import InfoGatheringTool


# ---------------------------------------------------------------------------
# Shared DB fixture (mirrors stage2 integration test pattern)
# ---------------------------------------------------------------------------

@pytest.fixture
async def db_engine(monkeypatch, tmp_path):
    db_file = tmp_path / "stage7_test.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file}",
        poolclass=NullPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("PRAGMA journal_mode=WAL"))
    Session = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def fake_get_session():
        async with Session() as s:
            yield s

    monkeypatch.setattr("workers.info_gathering.base_tool.get_session", fake_get_session)
    monkeypatch.setattr("workers.info_gathering.pipeline.get_session", fake_get_session)
    monkeypatch.setattr("workers.info_gathering.tools.execution_path_analyzer.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.pipeline_checkpoint.get_session", fake_get_session)
    monkeypatch.setattr("lib_webbh.get_session", fake_get_session)

    yield engine, Session
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_playbook(stage_name: str = "map_execution_paths", enabled: bool = True,
                   intensity: str = "low") -> dict:
    return {"workers": [{"name": "info_gathering", "stages": [
        {"name": stage_name, "enabled": enabled,
         "config": {"fingerprint_intensity": intensity}},
    ]}]}


def _katana_output(*urls: str) -> str:
    import json
    return "\n".join(json.dumps({"url": u}) for u in urls)


# ---------------------------------------------------------------------------
# I1 — happy path: crawl writes summary Observation
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_full_path_writes_summary_observation(db_engine):
    """Crawl + analyzer writes exactly one summary Observation for the subject asset."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Acme", base_domain="acme.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="acme.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="acme.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    katana_out = _katana_output(
        "https://acme.com/page",
        "https://acme.com/api/v1/users",
        "https://acme.com/login",
    )
    hakrawler_out = "https://acme.com/about\nhttps://acme.com/contact\n"

    def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return hakrawler_out

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="acme.com")

    async with Session() as sess:
        obs_rows = (
            await sess.execute(
                select(Observation).where(Observation.asset_id == asset_id)
            )
        ).scalars().all()

        summary_rows = [o for o in obs_rows if o.tech_stack and o.tech_stack.get("_probe") == "execution_paths"]
        assert len(summary_rows) == 1, f"expected 1 summary obs, got {len(summary_rows)}"

        summary = summary_rows[0]
        assert summary.asset_id == asset_id
        assert summary.tech_stack["total_paths"] > 0
        assert "categories" in summary.tech_stack


# ---------------------------------------------------------------------------
# I2 — WebSocket seeds are queried and passed to Katana
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_ws_seeds_queried_and_passed_to_katana(db_engine):
    """A websocket Asset in the DB must appear as a -u arg in Katana's command."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        ws = Asset(target_id=t.id, asset_type="websocket", asset_value="wss://example.com/ws")
        sess.add_all([a, ws])
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    captured_cmds: list[list[str]] = []

    async def _dispatch(cmd, **kwargs):
        captured_cmds.append(list(cmd))
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    katana_cmds = [c for c in captured_cmds if c and c[0] == "katana"]
    assert katana_cmds, "Katana was never called"
    katana_cmd_str = " ".join(katana_cmds[0])
    assert "wss://example.com/ws" in katana_cmd_str, (
        f"WS seed not in Katana command: {katana_cmd_str}"
    )


# ---------------------------------------------------------------------------
# I3 — Out-of-scope URLs are not saved
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_scope_violations_not_saved(db_engine):
    """URLs that fail scope_check must not appear as Asset rows in the DB."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")

    scope_manager = MagicMock(_in_scope_patterns={"example.com"})
    scope_manager.classify = MagicMock(side_effect=lambda url: MagicMock(
        classification="in-scope" if "example.com" in url else "out-of-scope"
    ))

    katana_out = _katana_output("https://evil.com/page", "https://example.com/safe")
    hakrawler_out = "https://evil.com/other\n"

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return hakrawler_out

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        all_assets = (
            await sess.execute(select(Asset).where(Asset.target_id == target_id))
        ).scalars().all()
        asset_values = {a.asset_value for a in all_assets}
        assert "https://evil.com/page" not in asset_values
        assert "https://evil.com/other" not in asset_values
        assert "https://example.com/safe" in asset_values


# ---------------------------------------------------------------------------
# I4 — SSE event includes paths_found stat
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_sse_event_includes_paths_found(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    events_published: list[dict] = []

    async def mock_push_task(stream, payload):
        events_published.append(payload)

    katana_out = _katana_output("https://example.com/p1", "https://example.com/p2")

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock(side_effect=mock_push_task)):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    stage7_events = [
        e for e in events_published
        if e.get("event") == "STAGE_COMPLETE" and e.get("stage") == "map_execution_paths"
    ]
    assert stage7_events, "No STAGE_COMPLETE event for map_execution_paths"
    stats = stage7_events[0]["stats"]
    assert "paths_found" in stats
    assert stats["paths_found"] >= 2


# ---------------------------------------------------------------------------
# I5 — Intensity medium → depth 3 in Katana command
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_intensity_medium_depth_3_in_katana_cmd(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = {"workers": [{"name": "info_gathering", "stages": [
        {"name": "map_execution_paths", "enabled": True,
         "config": {"fingerprint_intensity": "medium"}},
    ]}]}
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    captured: list[list[str]] = []

    async def _dispatch(cmd, **kwargs):
        captured.append(list(cmd))
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    katana_cmds = [c for c in captured if c and c[0] == "katana"]
    assert katana_cmds
    cmd = katana_cmds[0]
    assert cmd[cmd.index("-d") + 1] == "3"


# ---------------------------------------------------------------------------
# I6 — Partial summary when Hakrawler fails
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_partial_summary_when_hakrawler_fails(db_engine):
    """If Hakrawler times out, summary has partial=True; Katana results preserved."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        await sess.refresh(a)
        target_id, asset_id = t.id, a.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    katana_out = _katana_output("https://example.com/page")

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        raise TimeoutError("hakrawler timed out")

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        obs_rows = (
            await sess.execute(
                select(Observation).where(Observation.asset_id == asset_id)
            )
        ).scalars().all()
        summaries = [o for o in obs_rows if o.tech_stack and o.tech_stack.get("_probe") == "execution_paths"]
        assert summaries, "No summary observation written"
        summary = summaries[0]
        assert summary.tech_stack.get("partial") is True
        assert summary.tech_stack["tool_breakdown"]["hakrawler"]["errored"] is True
        assert summary.tech_stack["tool_breakdown"]["katana"]["errored"] is False
        assert summary.tech_stack["total_paths"] >= 1


# ---------------------------------------------------------------------------
# I7 — wss:// URL discovered during crawl saved as websocket asset type
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_ws_urls_saved_as_websocket_asset_type(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    katana_out = _katana_output("wss://example.com/realtime")
    hakrawler_out = ""

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return hakrawler_out

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        ws_assets = (
            await sess.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "websocket",
                )
            )
        ).scalars().all()
        ws_values = {a.asset_value for a in ws_assets}
        assert "wss://example.com/realtime" in ws_values


# ---------------------------------------------------------------------------
# I8 — FormMapper has no URL cap
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_no_url_cap_on_form_mapper(db_engine):
    """FormMapper must process more than 20 pre-existing URL assets."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="BigSite", base_domain="bigsite.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        assets = [
            Asset(target_id=t.id, asset_type="url", asset_value=f"https://bigsite.com/page{i}")
            for i in range(25)
        ]
        sess.add_all(assets)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.tools.form_mapper import FormMapper

    tool = FormMapper()
    target_obj = MagicMock(base_domain="bigsite.com")
    processed_urls: list[str] = []

    async def mock_extract(url: str):
        processed_urls.append(url)
        return []  # no forms found; we just count pages visited

    with patch.object(tool, "_extract_forms", side_effect=mock_extract):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_get_session():
            async with Session() as s:
                yield s

        with patch("workers.info_gathering.tools.form_mapper.get_session", fake_get_session):
            await tool.execute(target_id=target_id, target=target_obj)

    # 26 total: 1 base domain + 25 URL assets
    assert len(processed_urls) > 20, (
        f"FormMapper only processed {len(processed_urls)} URLs; URL cap may still be present"
    )


# ---------------------------------------------------------------------------
# I9 — Custom headers passed through to Katana
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_headers_passed_to_katana(db_engine):
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    captured: list[list[str]] = []

    async def _dispatch(cmd, **kwargs):
        captured.append(list(cmd))
        return ""

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(
            target_obj, scope_manager,
            headers={"Cookie": "session=abc123"},
            playbook=playbook,
            host="example.com",
        )

    katana_cmds = [c for c in captured if c and c[0] == "katana"]
    assert katana_cmds
    katana_str = " ".join(katana_cmds[0])
    assert "Cookie: session=abc123" in katana_str


# ---------------------------------------------------------------------------
# I10 — Dedup: same URL from both crawlers → single Asset row
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_stage7_dedup_does_not_create_duplicate_assets(db_engine):
    """The DB unique constraint must prevent duplicate Asset rows for the same URL."""
    engine, Session = db_engine

    async with Session() as sess:
        t = Target(company_name="Example", base_domain="example.com")
        sess.add(t)
        await sess.commit()
        await sess.refresh(t)
        a = Asset(target_id=t.id, asset_type="domain", asset_value="example.com")
        sess.add(a)
        await sess.commit()
        target_id = t.id

    from workers.info_gathering.pipeline import Pipeline

    pipeline = Pipeline(target_id=target_id, container_name="info_gathering")
    playbook = _make_playbook()
    target_obj = MagicMock(id=target_id, base_domain="example.com")
    scope_manager = MagicMock(_in_scope_patterns=set())

    # Both crawlers return the same URL
    shared_url = "https://example.com/shared-page"
    katana_out = _katana_output(shared_url)
    hakrawler_out = f"{shared_url}\n"

    async def _dispatch(cmd, **kwargs):
        if cmd[0] == "katana":
            return katana_out
        return hakrawler_out

    with patch.object(InfoGatheringTool, "run_subprocess", new=AsyncMock(side_effect=_dispatch)), \
         patch("workers.info_gathering.pipeline.push_task", new=AsyncMock()):
        await pipeline.run(target_obj, scope_manager, playbook=playbook, host="example.com")

    async with Session() as sess:
        rows = (
            await sess.execute(
                select(Asset).where(
                    Asset.target_id == target_id,
                    Asset.asset_value == shared_url,
                )
            )
        ).scalars().all()
        assert len(rows) == 1, f"Expected 1 Asset row for {shared_url}, got {len(rows)}"
```

- [ ] **Step 2: Run the integration tests**

```bash
pytest tests/test_info_gathering_stage7_integration.py -v --tb=short
```

Expected: All 10 tests PASS.

- [ ] **Step 3: Run the full test suite**

```bash
pytest tests/ -v --tb=short -q
```

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_info_gathering_stage7_integration.py
git commit -m "test(info-gathering): add Stage 7 integration tests (I1-I10)"
```

---

## Self-Review

**Spec coverage check:**

| Spec section | Task(s) |
|---|---|
| §1.3 — Asset rows, 1 summary Observation, SSE event | Task 8 I1, I4 |
| §2 — CrawlResult dataclass | Task 3 |
| §3.1 — Katana: host, WS seeds, intensity, headers, scope, returns CrawlResult | Task 4 |
| §3.2 — Hakrawler: host, intensity, headers, scope, returns CrawlResult | Task 5 |
| §3.4 — No URL caps | Task 2, I8 |
| §4 — ExecutionPathAnalyzer: categories, partial flag, tool_breakdown | Task 6 |
| §5.1 — url_classifier websocket + api_endpoint | Task 1 |
| §5.2 — ASSET_TYPES additions | Task 1 |
| §5.3 — Global URL cap removal | Task 2 |
| §6 — Pipeline: _fetch_ws_seeds, pre/post hooks, ws_seeds forwarding | Task 7 |
| §8.1 — 22 unit tests | Tasks 1, 4, 5, 6, 7 |
| §8.2 — 10 integration tests | Task 8 |

All spec requirements are covered. No gaps found.

**Placeholder scan:** No TBDs or incomplete steps. Every code step shows complete implementations.

**Type consistency:**
- `CrawlResult` is defined in `execution_path_analyzer.py` (Task 3) and imported by `katana.py` (Task 4), `hakrawler.py` (Task 5), and `pipeline.py` (Task 7) — consistent.
- `_fetch_ws_seeds` is defined in Task 7 Step 3c and tested in Task 7 Step 1 — consistent.
- `ws_seeds: list[str] | None = None` added to `_run_stage` in Task 7 Step 3d and forwarded as `ws_seeds=ws_seeds or []` in Step 3e — consistent.
- `_STAGE7_SECTION = "4.1.7"` constant matches the `STAGES` entry in `pipeline.py` — consistent.
