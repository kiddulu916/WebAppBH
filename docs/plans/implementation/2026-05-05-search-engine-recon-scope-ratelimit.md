# Search Engine Recon, Scope Refactor & Rate Limiting — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Full OWASP WSTG-INFO-01 coverage in Stage 1, 3-tier scope classification with wildcard engine, iterative campaign expansion, and stackable rate limiting.

**Architecture:** Four independently shippable phases. Scope checking is split into two operations: fast synchronous pattern matching (called inline during tool execution) and async deep classification (run as a batch post-stage step). Rate limiting uses Redis sliding window counters shared across pipeline instances.

**Tech Stack:** Python 3.13, asyncio, aiohttp, Redis, SQLAlchemy (async), FastAPI, Next.js 16, React 19, Tailwind v4, Zustand

**Design doc:** `docs/plans/design/2026-05-05-search-engine-recon-scope-ratelimit-design.md`

**Worktree:** `.worktrees/search-engine-recon` (branch: `feature/search-engine-recon-scope-ratelimit`)

**Baseline:** 958 passed, 1 pre-existing failure (`test_event_engine`), 2 skipped

---

## Phase A: Foundation (DB Schema + Wildcard Engine + Basic Scope)

Everything else builds on this. Ships independently.

---

### Task 1: Asset Model Schema Changes

**Files:**
- Modify: `shared/lib_webbh/database.py:210-234`
- Create: `alembic/versions/xxxx_add_scope_classification_to_asset.py`
- Test: `tests/test_database_scope_fields.py`

**Step 1: Write failing test for new Asset columns**

```python
# tests/test_database_scope_fields.py
import pytest
from sqlalchemy import inspect
from lib_webbh import Asset

def test_asset_has_scope_classification_column():
    mapper = inspect(Asset)
    columns = {c.key for c in mapper.columns}
    assert "scope_classification" in columns

def test_asset_has_associated_with_id_column():
    mapper = inspect(Asset)
    columns = {c.key for c in mapper.columns}
    assert "associated_with_id" in columns

def test_asset_has_association_method_column():
    mapper = inspect(Asset)
    columns = {c.key for c in mapper.columns}
    assert "association_method" in columns

@pytest.mark.anyio
async def test_asset_scope_classification_defaults_to_pending(db_session):
    from lib_webbh import Target
    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()
    asset = Asset(target_id=target.id, asset_type="domain", asset_value="test.com", source_tool="test")
    db_session.add(asset)
    await db_session.flush()
    assert asset.scope_classification == "pending"

@pytest.mark.anyio
async def test_asset_associated_with_relationship(db_session):
    from lib_webbh import Target
    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()
    parent = Asset(target_id=target.id, asset_type="domain", asset_value="test.com", source_tool="test")
    db_session.add(parent)
    await db_session.flush()
    child = Asset(
        target_id=target.id, asset_type="ip", asset_value="1.2.3.4",
        source_tool="dns", scope_classification="associated",
        associated_with_id=parent.id, association_method="dns_resolution",
    )
    db_session.add(child)
    await db_session.flush()
    assert child.associated_with_id == parent.id
    assert child.association_method == "dns_resolution"

@pytest.mark.anyio
async def test_deleting_parent_asset_nullifies_children(db_session):
    """Deleting a parent asset sets associated_with_id to NULL on children, not cascade delete."""
    from lib_webbh import Target
    target = Target(company_name="Test", base_domain="test.com")
    db_session.add(target)
    await db_session.flush()
    parent = Asset(target_id=target.id, asset_type="domain", asset_value="test.com", source_tool="test")
    db_session.add(parent)
    await db_session.flush()
    child = Asset(
        target_id=target.id, asset_type="ip", asset_value="1.2.3.4",
        source_tool="dns", associated_with_id=parent.id,
    )
    db_session.add(child)
    await db_session.flush()
    child_id = child.id
    await db_session.delete(parent)
    await db_session.flush()
    refreshed = await db_session.get(Asset, child_id)
    assert refreshed is not None
    assert refreshed.associated_with_id is None
```

**Step 2: Run tests — verify they fail**

```bash
pytest tests/test_database_scope_fields.py -v
```

Expected: FAIL — columns don't exist yet.

**Step 3: Add columns to Asset model**

In `shared/lib_webbh/database.py`, add to the `Asset` class (around line 225):

```python
scope_classification = Column(String(20), default="pending", server_default="pending", nullable=False)
associated_with_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
association_method = Column(String(50), nullable=True)

# Self-referential relationship
associated_with = relationship("Asset", remote_side="Asset.id", foreign_keys=[associated_with_id])
```

Key: `ondelete="SET NULL"` — deleting a parent asset nullifies children's FK, does NOT cascade delete the children.

Valid values for `scope_classification`: `"pending"`, `"in-scope"`, `"associated"`, `"undetermined"`, `"out-of-scope"`.

**Step 4: Run tests — verify they pass**

```bash
pytest tests/test_database_scope_fields.py -v
```

Expected: ALL PASS

**Step 5: Generate alembic migration**

```bash
cd /path/to/worktree
alembic revision --autogenerate -m "add scope_classification and association fields to asset"
```

Review the generated migration file. Ensure it has:
- `op.add_column('assets', sa.Column('scope_classification', sa.String(20), server_default='pending', nullable=False))`
- `op.add_column('assets', sa.Column('associated_with_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='SET NULL'), nullable=True))`
- `op.add_column('assets', sa.Column('association_method', sa.String(50), nullable=True))`

**Step 6: Run full test suite to check for regressions**

```bash
pytest tests/ --ignore=tests/e2e --ignore=tests/integration -q
```

Expected: 958+ passed (same as baseline + new tests), 0 new failures.

**Step 7: Commit**

```bash
git add shared/lib_webbh/database.py tests/test_database_scope_fields.py alembic/versions/
git commit -m "feat(db): add scope_classification and association tracking to Asset model"
```

---

### Task 2: Wildcard Pattern Engine

The core matching engine. Pure functions, no I/O, highly testable.

**Files:**
- Create: `shared/lib_webbh/wildcard.py`
- Test: `tests/test_wildcard.py`

**Step 1: Write comprehensive failing tests**

```python
# tests/test_wildcard.py
import pytest
from lib_webbh.wildcard import match_domain, match_ip, match_path, match_pattern

class TestDomainWildcards:
    def test_exact_match(self):
        assert match_domain("example.com", "example.com") is True

    def test_exact_no_match(self):
        assert match_domain("other.com", "example.com") is False

    def test_star_wildcard(self):
        assert match_domain("api.example.com", "*.example.com") is True

    def test_star_wildcard_no_match_base(self):
        assert match_domain("example.com", "*.example.com") is False

    def test_star_wildcard_nested_subdomain(self):
        assert match_domain("a.b.example.com", "*.example.com") is True

    def test_doublestar_alias(self):
        assert match_domain("api.example.com", "**.example.com") is True

    def test_doublestar_nested(self):
        assert match_domain("a.b.c.example.com", "**.example.com") is True


class TestIPWildcards:
    def test_exact_ip(self):
        assert match_ip("10.0.0.1", "10.0.0.1") is True

    def test_exact_ip_no_match(self):
        assert match_ip("10.0.0.2", "10.0.0.1") is False

    def test_cidr(self):
        assert match_ip("192.168.1.50", "192.168.0.0/16") is True

    def test_cidr_no_match(self):
        assert match_ip("10.0.0.1", "192.168.0.0/16") is False

    def test_single_octet_wildcard(self):
        assert match_ip("123.99.123.123", "123.*.123.123") is True

    def test_single_octet_wildcard_no_match(self):
        assert match_ip("124.99.123.123", "123.*.123.123") is False

    def test_multi_octet_wildcard(self):
        assert match_ip("123.123.50.60", "123.123.*.*") is True

    def test_first_two_octets_wildcard(self):
        assert match_ip("10.20.123.123", "*.*.123.123") is True

    def test_all_wildcards(self):
        assert match_ip("1.2.3.4", "*.*.*.*") is True

    def test_mixed_wildcards(self):
        assert match_ip("10.123.20.123", "*.123.*.123") is True

    def test_mixed_wildcards_no_match(self):
        assert match_ip("10.124.20.123", "*.123.*.123") is False

    def test_first_octet_wildcard(self):
        assert match_ip("99.0.0.1", "*.0.0.1") is True

    def test_last_three_wildcards(self):
        assert match_ip("123.1.2.3", "123.*.*.*") is True


class TestPathWildcards:
    def test_trailing_star(self):
        assert match_path("example.com/api/v1/users", "example.com/api/v1/*") is True

    def test_trailing_star_no_match_parent(self):
        assert match_path("example.com/api/v2/users", "example.com/api/v1/*") is False

    def test_extension_wildcard(self):
        assert match_path("example.com/api/v1/data.json", "example.com/api/v1/*.json") is True

    def test_extension_wildcard_wrong_ext(self):
        assert match_path("example.com/api/v1/data.xml", "example.com/api/v1/*.json") is False

    def test_filename_wildcard(self):
        assert match_path("example.com/api/v1/file.txt", "example.com/api/v1/file.*") is True

    def test_single_segment_wildcard(self):
        assert match_path("example.com/foo/config", "example.com/*/config") is True

    def test_globstar_any_domain(self):
        assert match_path("example.com/api/v1/foo", "**/api/v1/*") is True
        assert match_path("other.com/prefix/api/v1/bar", "**/api/v1/*") is True

    def test_globstar_recursive_path(self):
        assert match_path("example.com/a/secret", "example.com/**/secret") is True
        assert match_path("example.com/a/b/c/secret", "example.com/**/secret") is True
        assert match_path("example.com/secret", "example.com/**/secret") is True


class TestMatchPattern:
    """Top-level dispatcher that auto-detects pattern type."""

    def test_detects_domain_pattern(self):
        assert match_pattern("api.example.com", "*.example.com") is True

    def test_detects_ip_pattern(self):
        assert match_pattern("192.168.1.1", "192.168.0.0/16") is True

    def test_detects_ip_wildcard(self):
        assert match_pattern("10.0.0.1", "10.*.*.*") is True

    def test_detects_path_pattern(self):
        assert match_pattern("example.com/api/v1/foo", "example.com/api/v1/*") is True

    def test_detects_globstar(self):
        assert match_pattern("other.com/deep/api/v1/x", "**/api/v1/*") is True

    def test_out_of_scope_checked_first(self):
        """Utility test: match_pattern is just matching. Scope priority is handled by ScopeManager."""
        # This just verifies the function works for out-of-scope patterns too
        assert match_pattern("example.com/api/v1/admin", "example.com/api/v1/*") is True
```

**Step 2: Run tests — verify they fail**

```bash
pytest tests/test_wildcard.py -v
```

Expected: FAIL — module doesn't exist.

**Step 3: Implement wildcard engine**

Create `shared/lib_webbh/wildcard.py` with these functions:

- `match_domain(value: str, pattern: str) -> bool` — handles `*` and `**` prefix wildcards
- `match_ip(value: str, pattern: str) -> bool` — handles exact, CIDR (via `netaddr`), octet wildcards (split on `.`, compare each octet, `*` matches any)
- `match_path(value: str, pattern: str) -> bool` — handles `*` (single segment/filename), `**` (recursive/globstar), extension wildcards. Use `fnmatch` or manual glob logic
- `match_pattern(value: str, pattern: str) -> bool` — auto-detect pattern type and dispatch to appropriate function. Detection order: if pattern contains `/` → path, if pattern looks like IP/CIDR (digits and dots and `/` and `*`) → IP, else → domain

Export from `shared/lib_webbh/__init__.py`.

**Step 4: Run tests — verify they pass**

```bash
pytest tests/test_wildcard.py -v
```

Expected: ALL PASS

**Step 5: Commit**

```bash
git add shared/lib_webbh/wildcard.py shared/lib_webbh/__init__.py tests/test_wildcard.py
git commit -m "feat(scope): add wildcard pattern engine with domain/IP/path glob support"
```

---

### Task 3: ScopeManager Refactor — Fast Pattern Classification

Refactor `ScopeManager` to use the wildcard engine and return 3-tier classifications. This task covers Layer 1 (direct match) only — the fast, synchronous, inline check.

**Files:**
- Modify: `shared/lib_webbh/scope.py:29-245`
- Test: `tests/test_scope_classification.py`

**Step 1: Write failing tests for new classification behavior**

```python
# tests/test_scope_classification.py
import pytest
from lib_webbh.scope import ScopeManager, ScopeResult

class TestPatternClassification:
    def setup_method(self):
        self.sm = ScopeManager(
            in_scope=["*.example.com", "example.com", "10.0.0.0/8", "123.*.0.*"],
            out_of_scope=["staging.example.com", "example.com/api/v1/internal/*"],
        )

    def test_exact_domain_in_scope(self):
        result = self.sm.classify("example.com")
        assert result.classification == "in-scope"

    def test_wildcard_subdomain_in_scope(self):
        result = self.sm.classify("api.example.com")
        assert result.classification == "in-scope"

    def test_out_of_scope_takes_priority(self):
        result = self.sm.classify("staging.example.com")
        assert result.classification == "out-of-scope"

    def test_path_out_of_scope(self):
        result = self.sm.classify("example.com/api/v1/internal/secret")
        assert result.classification == "out-of-scope"

    def test_ip_cidr_in_scope(self):
        result = self.sm.classify("10.50.30.1")
        assert result.classification == "in-scope"

    def test_ip_octet_wildcard_in_scope(self):
        result = self.sm.classify("123.99.0.50")
        assert result.classification == "in-scope"

    def test_unknown_domain_is_pending(self):
        result = self.sm.classify("other.com")
        assert result.classification == "pending"

    def test_unknown_ip_is_pending(self):
        result = self.sm.classify("200.200.200.200")
        assert result.classification == "pending"

    def test_result_includes_matched_pattern(self):
        result = self.sm.classify("api.example.com")
        assert result.matched_pattern == "*.example.com"

    def test_result_matched_pattern_none_for_pending(self):
        result = self.sm.classify("other.com")
        assert result.matched_pattern is None
```

Key behavior: `classify()` returns `ScopeResult` with `classification` field. Values returned by Layer 1 only: `"in-scope"`, `"out-of-scope"`, or `"pending"` (not yet `"undetermined"` or `"associated"` — those come from deep classification).

**Step 2: Run tests — verify they fail**

```bash
pytest tests/test_scope_classification.py -v
```

**Step 3: Refactor ScopeManager**

Modify `shared/lib_webbh/scope.py`:

- Update `ScopeResult` dataclass to include `classification: str` and `matched_pattern: str | None`
- `__init__` accepts `in_scope: list[str]` and `out_of_scope: list[str]` (raw patterns)
- Add `classify(value: str) -> ScopeResult` method:
  1. Check out-of-scope patterns first (using `match_pattern` from wildcard engine)
  2. If any match → return `ScopeResult(classification="out-of-scope", matched_pattern=pattern)`
  3. Check in-scope patterns
  4. If any match → return `ScopeResult(classification="in-scope", matched_pattern=pattern)`
  5. No match → return `ScopeResult(classification="pending", matched_pattern=None)`
- Keep backward compatibility: existing `is_in_scope()` method delegates to `classify()` and returns `bool`

**Step 4: Run tests — verify they pass**

```bash
pytest tests/test_scope_classification.py -v
```

**Step 5: Run full suite to check regressions**

```bash
pytest tests/ --ignore=tests/e2e --ignore=tests/integration -q
```

Existing tests that call `is_in_scope()` must still pass.

**Step 6: Commit**

```bash
git add shared/lib_webbh/scope.py tests/test_scope_classification.py
git commit -m "feat(scope): refactor ScopeManager with 3-tier classification and wildcard support"
```

---

### Task 4: Deep Scope Classifier (Layers 2-7)

Async batch classifier that processes `"pending"` assets after each pipeline stage. Runs DNS, TLS, HTTP, WHOIS, and header checks to classify assets as `"associated"` or `"undetermined"`.

**Files:**
- Create: `shared/lib_webbh/deep_classifier.py`
- Test: `tests/test_deep_classifier.py`

**Step 1: Write failing tests**

Test each layer with mocked network calls:

```python
# tests/test_deep_classifier.py
import pytest
from unittest.mock import AsyncMock, patch
from lib_webbh.deep_classifier import DeepClassifier

@pytest.fixture
def classifier():
    return DeepClassifier(
        in_scope_domains=["example.com", "*.example.com"],
        in_scope_ips=["10.0.0.0/8"],
    )

@pytest.mark.anyio
async def test_dns_resolution_associates_ip(classifier):
    """Layer 2: IP that reverse-resolves to in-scope domain → associated."""
    with patch("lib_webbh.deep_classifier.reverse_dns", new_callable=AsyncMock, return_value="lb1.example.com"):
        result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
    assert result.classification == "associated"
    assert result.association_method == "dns_resolution"

@pytest.mark.anyio
async def test_tls_san_associates_ip(classifier):
    """Layer 3: IP with cert SAN matching in-scope domain → associated."""
    with patch("lib_webbh.deep_classifier.reverse_dns", new_callable=AsyncMock, return_value=None), \
         patch("lib_webbh.deep_classifier.get_tls_sans", new_callable=AsyncMock, return_value=["*.example.com", "example.com"]):
        result = await classifier.classify_deep("52.10.30.40", asset_type="ip")
    assert result.classification == "associated"
    assert result.association_method == "tls_san"

@pytest.mark.anyio
async def test_all_layers_fail_returns_undetermined(classifier):
    """All 7 layers fail → undetermined."""
    with patch("lib_webbh.deep_classifier.reverse_dns", new_callable=AsyncMock, return_value=None), \
         patch("lib_webbh.deep_classifier.get_tls_sans", new_callable=AsyncMock, return_value=[]), \
         patch("lib_webbh.deep_classifier.check_http_hosting", new_callable=AsyncMock, return_value=None), \
         patch("lib_webbh.deep_classifier.lookup_asn", new_callable=AsyncMock, return_value=None), \
         patch("lib_webbh.deep_classifier.check_header_linkage", new_callable=AsyncMock, return_value=None):
        result = await classifier.classify_deep("200.200.200.200", asset_type="ip")
    assert result.classification == "undetermined"
    assert result.association_method is None

@pytest.mark.anyio
async def test_discovered_from_associates(classifier):
    """Layer 7: Asset discovered from in-scope parent → associated."""
    result = await classifier.classify_deep(
        "cdn.otherdomain.com", asset_type="domain",
        discovered_from_scope="in-scope",
    )
    assert result.classification == "associated"
    assert result.association_method == "discovered_from"
```

**Step 2: Run tests — verify they fail**

```bash
pytest tests/test_deep_classifier.py -v
```

**Step 3: Implement DeepClassifier**

Create `shared/lib_webbh/deep_classifier.py`:

- Class `DeepClassifier` — initialized with in-scope domains and IPs (from ScopeManager)
- Method `async classify_deep(value, asset_type, discovered_from_scope=None) -> DeepResult`
- Each layer is a separate private async method, called in order, short-circuits on first match
- Helper functions (module-level, mockable): `reverse_dns()`, `get_tls_sans()`, `check_http_hosting()`, `lookup_asn()`, `check_header_linkage()`
- Each helper has a 5-second timeout, returns `None` on failure (never blocks the classifier)
- `DeepResult` dataclass: `classification: str`, `association_method: str | None`, `associated_value: str | None` (the in-scope asset it's linked to)

**Step 4: Run tests — verify they pass**

```bash
pytest tests/test_deep_classifier.py -v
```

**Step 5: Commit**

```bash
git add shared/lib_webbh/deep_classifier.py tests/test_deep_classifier.py
git commit -m "feat(scope): add async deep classifier with 7-layer inference engine"
```

---

### Task 5: Integrate Classification into Pipeline

Wire the fast classifier (inline) and deep classifier (post-stage batch) into the pipeline.

**Files:**
- Modify: `workers/info_gathering/base_tool.py:57-60` (scope_check to use classify)
- Modify: `workers/info_gathering/pipeline.py:120-150` (_run_stage to add batch classification)
- Test: `tests/test_pipeline_classification.py`

**Step 1: Write failing test**

```python
# tests/test_pipeline_classification.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

@pytest.mark.anyio
async def test_save_asset_sets_pending_classification(db_session):
    """Assets saved by tools should have scope_classification='pending' initially."""
    # Test that base_tool.save_asset() sets scope_classification based on fast classify
    pass  # Implement: create tool instance, call save_asset, verify classification

@pytest.mark.anyio
async def test_post_stage_classifies_pending_assets():
    """After a stage completes, all 'pending' assets should be deep-classified."""
    pass  # Implement: mock deep classifier, verify it's called for pending assets
```

**Step 2: Implement changes**

In `base_tool.py` `save_asset()`:
- After creating the Asset, call `scope_manager.classify(asset_value)` (fast, sync)
- Set `asset.scope_classification` to the result
- If result is `"in-scope"` or `"out-of-scope"`, it's final
- If result is `"pending"`, leave it for the deep classifier

In `pipeline.py` `_run_stage()`:
- After `asyncio.gather()` completes for all tools in the stage, add a batch step:
- Query all Assets for this target with `scope_classification="pending"`
- Run `DeepClassifier.classify_deep()` on each (with concurrency limit of 5)
- Update each asset's `scope_classification`, `associated_with_id`, `association_method`

**Step 3: Run tests, verify pass, run full suite**

**Step 4: Commit**

```bash
git commit -m "feat(pipeline): integrate fast + deep scope classification into pipeline stages"
```

---

## Phase B: Stage 1 Tools + API Key Management

New and rewritten tools for WSTG 4.1.1. Ships independently after Phase A.

---

### Task 6: DorkEngine Rewrite

**Files:**
- Rewrite: `workers/info_gathering/tools/dork_engine.py`
- Create: `workers/info_gathering/tools/dork_patterns.py` (curated dork library)
- Test: `tests/test_dork_engine.py`

**Step 1: Write failing tests**

```python
# tests/test_dork_engine.py
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.dork_engine import DorkEngine
from workers.info_gathering.tools.dork_patterns import DORK_CATEGORIES, get_dorks_for_domain

class TestDorkPatterns:
    def test_categories_count(self):
        assert len(DORK_CATEGORIES) == 8

    def test_get_dorks_interpolates_domain(self):
        dorks = get_dorks_for_domain("example.com")
        assert any("site:example.com" in d for d in dorks)
        assert len(dorks) >= 60  # minimum viable set

    def test_all_dorks_contain_domain_reference(self):
        dorks = get_dorks_for_domain("example.com")
        # Most dorks should reference the domain (some globstar patterns may not)
        domain_dorks = [d for d in dorks if "example.com" in d]
        assert len(domain_dorks) >= len(dorks) * 0.8

class TestDorkEngine:
    @pytest.mark.anyio
    async def test_rotates_across_engines(self):
        """Queries should be distributed across Google, Bing, DuckDuckGo."""
        engine = DorkEngine()
        with patch.object(engine, "_scrape_engine", new_callable=AsyncMock, return_value=[]):
            await engine.execute(target_id=1, domain="example.com", scope_manager=AsyncMock())
            calls = engine._scrape_engine.call_args_list
            engines_used = {c.args[0] for c in calls}  # first arg is engine name
            assert len(engines_used) >= 2  # at least 2 engines used

    @pytest.mark.anyio
    async def test_scope_checks_results(self):
        """Discovered URLs are scope-checked before saving."""
        engine = DorkEngine()
        mock_scope = AsyncMock()
        fake_results = [{"url": "https://example.com/admin", "title": "Admin", "snippet": "..."}]
        with patch.object(engine, "_scrape_engine", new_callable=AsyncMock, return_value=fake_results):
            await engine.execute(target_id=1, domain="example.com", scope_manager=mock_scope)
        # save_asset should have been called
```

**Step 2: Run tests — verify they fail**

**Step 3: Implement**

`dork_patterns.py`:
- `DORK_CATEGORIES` dict — 8 categories, each a list of template strings with `{domain}` placeholder
- `get_dorks_for_domain(domain: str) -> list[str]` — interpolates domain into all templates, returns flat list

`dork_engine.py`:
- `DorkEngine(InfoGatheringTool)` class
- `execute()`: get dorks → round-robin assign to engines → scrape with delays → scope-check → save
- `_scrape_engine(engine: str, query: str) -> list[dict]` — dispatches to `_scrape_google`, `_scrape_bing`, `_scrape_duckduckgo`
- Each scraper: HTTP GET with random User-Agent, parse HTML response for result URLs/titles/snippets
- Random delay 3-7 seconds between requests
- On 429/503/CAPTCHA detection → redistribute remaining queries to other engines
- User-Agent pool: 10 real Chrome/Firefox/Safari strings

**Step 4: Run tests — verify pass**

**Step 5: Commit**

```bash
git commit -m "feat(tools): rewrite DorkEngine with multi-engine scraping and GHDB dork library"
```

---

### Task 7: ArchiveProber Enhancement

**Files:**
- Modify: `workers/info_gathering/tools/archive_prober.py`
- Test: `tests/test_archive_prober.py`

**Step 1: Write failing tests for cached content retrieval**

```python
# tests/test_archive_prober.py
import pytest
from unittest.mock import AsyncMock, patch

SENSITIVE_EXTENSIONS = {".env", ".sql", ".bak", ".conf", ".key", ".pem", ".log"}

class TestArchiveProberCachedContent:
    @pytest.mark.anyio
    async def test_fetches_cached_content_for_sensitive_files(self):
        """Should fetch Wayback cached content for .env, .sql, etc."""
        pass

    @pytest.mark.anyio
    async def test_limits_cached_fetches_to_20(self):
        """Should not fetch more than 20 cached pages per target."""
        pass

    @pytest.mark.anyio
    async def test_saves_observation_with_snippet(self):
        """Cached content saved as Observation with first 2KB snippet."""
        pass
```

**Step 2: Implement** — add sensitive extension filter + Wayback snapshot fetch + 20-page cap + Observation save with snippet

**Step 3: Test, verify, commit**

```bash
git commit -m "feat(tools): enhance ArchiveProber with cached content retrieval for sensitive files"
```

---

### Task 8: CacheProber (new)

**Files:**
- Create: `workers/info_gathering/tools/cache_prober.py`
- Test: `tests/test_cache_prober.py`

**Step 1: Write failing tests**

```python
# tests/test_cache_prober.py
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.cache_prober import CacheProber

class TestCacheProber:
    @pytest.mark.anyio
    async def test_queries_archive_ph(self):
        """Should query archive.ph/newest/{domain}."""
        pass

    @pytest.mark.anyio
    async def test_extracts_cached_urls(self):
        """Should parse archive.ph response for captured URL list."""
        pass

    @pytest.mark.anyio
    async def test_filters_sensitive_extensions_only(self):
        """Should only fetch content for sensitive file extensions."""
        pass
```

**Step 2: Implement** `CacheProber(InfoGatheringTool)`:
- `execute()`: fetch `archive.ph/newest/{domain}`, parse HTML for snapshot URLs, filter for sensitive extensions, fetch and save

**Step 3: Test, verify, commit**

```bash
git commit -m "feat(tools): add CacheProber for archive.ph snapshot discovery"
```

---

### Task 9: ShodanSearcher (new, optional)

**Files:**
- Create: `workers/info_gathering/tools/shodan_searcher.py`
- Test: `tests/test_shodan_searcher.py`

**Step 1: Write failing tests**

```python
# tests/test_shodan_searcher.py
import pytest
from unittest.mock import AsyncMock, patch
from workers.info_gathering.tools.shodan_searcher import ShodanSearcher

class TestShodanSearcher:
    @pytest.mark.anyio
    async def test_skips_when_no_api_key(self):
        """Should return None and log info when SHODAN_API_KEY not set."""
        with patch.dict("os.environ", {}, clear=True):
            tool = ShodanSearcher()
            result = await tool.execute(target_id=1, domain="example.com", scope_manager=AsyncMock())
        assert result is None

    @pytest.mark.anyio
    async def test_resolves_domain_to_ips(self):
        """Should call /dns/resolve to get IPs for domain."""
        pass

    @pytest.mark.anyio
    async def test_saves_port_and_service_data(self):
        """Should save open ports and service banners as observations."""
        pass

    @pytest.mark.anyio
    async def test_respects_rate_limit(self):
        """Should sleep 1 second between API calls."""
        pass
```

**Step 2: Implement** `ShodanSearcher(InfoGatheringTool)`:
- Check `os.environ.get("SHODAN_API_KEY")` → skip if not set
- `/dns/resolve` → get IPs → scope-check each → `/shodan/host/{ip}` for each → save Assets + Observations
- 1 req/s rate limit

**Step 3: Test, verify, commit**

```bash
git commit -m "feat(tools): add optional ShodanSearcher for host/port/service discovery"
```

---

### Task 10: CensysSearcher (new, optional)

**Files:**
- Create: `workers/info_gathering/tools/censys_searcher.py`
- Test: `tests/test_censys_searcher.py`

Same pattern as ShodanSearcher:
- Skip if `CENSYS_API_ID` or `CENSYS_API_SECRET` not set
- `/v2/hosts/search?q={domain}` → `/v2/hosts/{ip}` per host
- Save IPs, services, TLS SANs
- 0.5s between calls

**Commit:**

```bash
git commit -m "feat(tools): add optional CensysSearcher for infrastructure and TLS discovery"
```

---

### Task 11: SecurityTrailsSearcher (new, optional)

**Files:**
- Create: `workers/info_gathering/tools/securitytrails_searcher.py`
- Test: `tests/test_securitytrails_searcher.py`

Same pattern:
- Skip if `SECURITYTRAILS_API_KEY` not set
- `/v1/domain/{domain}` → DNS records
- `/v1/domain/{domain}/subdomains` → subdomains
- `/v1/history/{domain}/dns/a` → historical IPs
- `/v1/domain/{domain}/associated` → associated domains
- 2s between calls

**Commit:**

```bash
git commit -m "feat(tools): add optional SecurityTrailsSearcher for DNS history and domain associations"
```

---

### Task 12: Pipeline & Concurrency Updates

**Files:**
- Modify: `workers/info_gathering/pipeline.py:40-51` (STAGES list)
- Modify: `workers/info_gathering/concurrency.py:8-35` (TOOL_WEIGHTS)
- Test: `tests/test_pipeline_stage1.py`

**Step 1: Write test**

```python
# tests/test_pipeline_stage1.py
from workers.info_gathering.pipeline import STAGES
from workers.info_gathering.concurrency import TOOL_WEIGHTS

def test_stage1_has_six_tools():
    stage1 = STAGES[0]
    assert stage1.name == "search_engine_recon"
    assert len(stage1.tools) == 6

def test_new_tools_are_light_weight():
    for name in ["CacheProber", "ShodanSearcher", "CensysSearcher", "SecurityTrailsSearcher"]:
        assert TOOL_WEIGHTS[name] == "LIGHT"
```

**Step 2: Update STAGES** — add CacheProber, ShodanSearcher, CensysSearcher, SecurityTrailsSearcher to Stage 1 tools list

**Step 3: Update TOOL_WEIGHTS** — add all 4 new tools as LIGHT

**Step 4: Test, verify, commit**

```bash
git commit -m "feat(pipeline): add 4 new tools to Stage 1 and register as LIGHT weight"
```

---

### Task 13: API Key Management — Orchestrator + docker-compose

**Files:**
- Modify: `orchestrator/main.py:2150-2184` (api_keys endpoints)
- Modify: `docker-compose.yml:60-71,117-124` (env vars)
- Test: `tests/test_api_keys_endpoint.py`

**Step 1: Write failing tests**

```python
# tests/test_api_keys_endpoint.py
import pytest
from httpx import AsyncClient

@pytest.mark.anyio
async def test_get_api_key_status_includes_censys(client: AsyncClient):
    resp = await client.get("/api/v1/config/api_keys")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert "censys" in keys
    assert "shodan" in keys
    assert "securitytrails" in keys

@pytest.mark.anyio
async def test_put_api_keys_accepts_censys(client: AsyncClient):
    resp = await client.put("/api/v1/config/api_keys", json={
        "censys_api_id": "test-id",
        "censys_api_secret": "test-secret",
    })
    assert resp.status_code == 200
    assert resp.json()["keys"]["censys"] is True

@pytest.mark.anyio
async def test_put_empty_string_does_not_overwrite(client: AsyncClient):
    # Set a key first
    await client.put("/api/v1/config/api_keys", json={"shodan_api_key": "real-key"})
    # Send empty string — should not overwrite
    await client.put("/api/v1/config/api_keys", json={"shodan_api_key": ""})
    resp = await client.get("/api/v1/config/api_keys")
    assert resp.json()["keys"]["shodan"] is True
```

**Step 2: Implement**

- Extend GET endpoint to check `CENSYS_API_ID` and `CENSYS_API_SECRET` env vars. `censys: true` only when BOTH are set.
- Extend PUT endpoint to accept `censys_api_id` and `censys_api_secret` fields. Only write non-empty values to `.env.intel`.
- Add `CENSYS_API_ID` and `CENSYS_API_SECRET` to docker-compose.yml for orchestrator and info_gathering services.

**Step 3: Test, verify, commit**

```bash
git commit -m "feat(api): extend api_keys endpoints for Censys and add env vars to docker-compose"
```

---

### Task 14: Dashboard — API Key UI Updates

**Files:**
- Modify: `dashboard/src/lib/api.ts:531-539` (updateApiKeys type)
- Modify: `dashboard/src/app/settings/page.tsx:123-278` (add Censys fields)
- Modify: `dashboard/src/components/campaign/ScopeBuilder.tsx:68-80,343-370` (add Censys fields)

**Step 1: Update API client types**

In `api.ts`, extend `updateApiKeys` to accept `censys_api_id` and `censys_api_secret`.

**Step 2: Update Settings page**

- Add `censysId` and `censysSecret` state vars
- Add `showCensysId` and `showCensysSecret` visibility toggles
- Add two new input rows in the API Keys section following the existing Shodan/SecurityTrails pattern
- Green badge "API key configured" + "Change" button when key is set
- Normal password input when not set
- On save: only include non-empty values in payload

**Step 3: Update ScopeBuilder Step 0**

- Add `censysId`, `censysSecret` state vars
- Add `censys` to `apiKeyStatus` state
- Add two new fields following existing pattern (status badge / input)
- On submit: include in api key save payload (non-empty only)

**Step 4: Visual verification**

```bash
cd dashboard && npm run dev
```

Open `http://localhost:3000/settings` — verify Censys fields appear with correct badge/input behavior.
Open `http://localhost:3000/campaign/new` — verify Censys fields in Step 0.

**Step 5: Commit**

```bash
git commit -m "feat(dashboard): add Censys API key fields to settings and campaign creation"
```

---

## Phase C: Rate Limiting System

Ships independently after Phase A.

---

### Task 15: Rate Limit Core — Redis Sliding Window

**Files:**
- Create: `shared/lib_webbh/rate_limiter.py`
- Test: `tests/test_rate_limiter.py`

**Step 1: Write failing tests**

```python
# tests/test_rate_limiter.py
import pytest
from unittest.mock import AsyncMock, patch
from lib_webbh.rate_limiter import RateLimiter, parse_rate_rule

class TestParseRateRule:
    def test_req_per_second(self):
        rule = parse_rate_rule({"amount": 50, "unit": "req/s"})
        assert rule.amount == 50
        assert rule.window_seconds == 1
        assert rule.rule_type == "request"

    def test_req_per_custom_window(self):
        rule = parse_rate_rule({"amount": 100, "unit": "req/5s"})
        assert rule.amount == 100
        assert rule.window_seconds == 5

    def test_req_per_minute(self):
        rule = parse_rate_rule({"amount": 500, "unit": "req/min"})
        assert rule.window_seconds == 60

    def test_req_per_hour(self):
        rule = parse_rate_rule({"amount": 10000, "unit": "req/hr"})
        assert rule.window_seconds == 3600

    def test_req_per_day(self):
        rule = parse_rate_rule({"amount": 50000, "unit": "req/day"})
        assert rule.window_seconds == 86400

    def test_bytes_per_second(self):
        rule = parse_rate_rule({"amount": 500, "unit": "bytes/s"})
        assert rule.amount == 500
        assert rule.rule_type == "bandwidth"

    def test_kb_per_second(self):
        rule = parse_rate_rule({"amount": 100, "unit": "KB/s"})
        assert rule.amount == 100 * 1024

    def test_mb_per_second(self):
        rule = parse_rate_rule({"amount": 5, "unit": "MB/s"})
        assert rule.amount == 5 * 1024 * 1024

    def test_mb_per_custom_window(self):
        rule = parse_rate_rule({"amount": 10, "unit": "MB/30s"})
        assert rule.amount == 10 * 1024 * 1024
        assert rule.window_seconds == 30

class TestRateLimiter:
    @pytest.mark.anyio
    async def test_allows_within_limit(self):
        """Requests within the limit should proceed immediately."""
        pass  # mock Redis, verify no wait

    @pytest.mark.anyio
    async def test_blocks_when_limit_exceeded(self):
        """Requests exceeding the limit should wait."""
        pass  # mock Redis counter at limit, verify sleep called

    @pytest.mark.anyio
    async def test_multiple_rules_most_restrictive_wins(self):
        """When multiple rules exist, the most restrictive one blocks."""
        pass

    @pytest.mark.anyio
    async def test_bandwidth_rule_tracks_bytes(self):
        """Bandwidth rules should track response body size."""
        pass
```

**Step 2: Implement** `shared/lib_webbh/rate_limiter.py`:

- `RateRule` dataclass: `amount`, `window_seconds`, `rule_type` ("request" | "bandwidth")
- `parse_rate_rule(rule_dict) -> RateRule` — parses `{"amount": N, "unit": "..."}` format
- `RateLimiter` class:
  - `__init__(redis_client, campaign_id, rules: list[RateRule])`
  - `async acquire(response_bytes: int = 0)` — check all rules, wait if any exceeded
  - Uses Redis sorted sets for sliding window (ZADD timestamp, ZREMRANGEBYSCORE to trim window, ZCARD to count)
  - For bandwidth: sums byte values in window instead of counting

Export from `shared/lib_webbh/__init__.py`.

**Step 3: Test, verify, commit**

```bash
git commit -m "feat(ratelimit): add Redis sliding window rate limiter with stackable rules"
```

---

### Task 16: Campaign Model — Rate Limits Field

**Files:**
- Modify: `shared/lib_webbh/database.py` (Campaign model)
- Modify: `orchestrator/main.py` (campaign create/update endpoints)
- Create: `alembic/versions/xxxx_add_rate_limits_to_campaign.py`
- Test: `tests/test_campaign_rate_limits.py`

**Step 1: Add `rate_limits` JSON column to Campaign model**

Add alongside existing `rate_limit` integer field (keep both during migration):

```python
rate_limits = Column(JSON, default=[{"amount": 50, "unit": "req/s"}], nullable=True)
```

**Step 2: Update campaign create/update endpoints** to accept `rate_limits` array

**Step 3: Generate alembic migration**

**Step 4: Test, verify, commit**

```bash
git commit -m "feat(db): add rate_limits JSON field to Campaign model"
```

---

### Task 17: Dashboard — Rate Limit Builder UI

**Files:**
- Create: `dashboard/src/components/shared/RateLimitBuilder.tsx`
- Modify: `dashboard/src/app/settings/page.tsx` (add default rate limits section)
- Modify: `dashboard/src/components/campaign/ScopeBuilder.tsx` (add rate limit builder)

**Step 1: Build RateLimitBuilder component**

Reusable component used in both settings and campaign creation:
- Each rule is a row: number input (amount) + dropdown (unit: req/s, req/min, req/hr, req/day, req/Ns, bytes/s, KB/s, MB/s, KB/Ns, MB/min, MB/hr)
- "Add rule" button
- "Remove" button per row (hidden when only 1 rule)
- Props: `rules`, `onChange`, `label`

**Step 2: Add to Settings page** — "Default Rate Limits" section

**Step 3: Add to ScopeBuilder** — replaces single rate_limit number input

**Step 4: Visual verification** — dev server, check both locations

**Step 5: Commit**

```bash
git commit -m "feat(dashboard): add stackable rate limit builder to settings and campaign creation"
```

---

### Task 18: Integrate Rate Limiter into Pipeline

**Files:**
- Modify: `workers/info_gathering/main.py` (initialize rate limiter from campaign config)
- Modify: `workers/info_gathering/base_tool.py` (acquire rate limit before target-facing requests)

**Step 1: In `main.py`** — when starting pipeline, load campaign's `rate_limits` from DB, create `RateLimiter` instance, pass to pipeline

**Step 2: In `base_tool.py`** — add optional `rate_limiter` parameter to `run_subprocess()` and HTTP methods. Call `await rate_limiter.acquire()` before target-facing requests.

**Step 3: Test, verify, commit**

```bash
git commit -m "feat(pipeline): integrate rate limiter into tool execution"
```

---

## Phase D: Campaign Expansion + Assets Triage UI

Ships after Phases A and B.

---

### Task 19: Multi-Round Campaign Execution

**Files:**
- Modify: `workers/info_gathering/main.py` (add expansion loop)
- Test: `tests/test_campaign_expansion.py`

**Step 1: Write failing tests**

```python
# tests/test_campaign_expansion.py
import pytest

@pytest.mark.anyio
async def test_expansion_queues_in_scope_discoveries():
    """New in-scope assets discovered in round 1 get queued for round 2."""
    pass

@pytest.mark.anyio
async def test_expansion_queues_associated_discoveries():
    """Associated assets also get queued for pipeline runs."""
    pass

@pytest.mark.anyio
async def test_undetermined_assets_not_queued():
    """Undetermined assets are NOT auto-queued."""
    pass

@pytest.mark.anyio
async def test_max_rounds_safeguard():
    """Expansion stops after max_rounds (default 5)."""
    pass

@pytest.mark.anyio
async def test_convergence_stops_expansion():
    """Expansion stops when no new in-scope/associated assets found."""
    pass

@pytest.mark.anyio
async def test_deduplication():
    """An asset is never scanned twice."""
    pass
```

**Step 2: Implement expansion loop in `main.py`**

After the initial pipeline run completes:
1. Query new assets with `scope_classification in ("in-scope", "associated")` that haven't been scanned
2. For each, push a new task to `info_gathering_queue`
3. Track round number in `job_state` metadata
4. Check safeguards: max rounds (5), max assets per round (500)
5. Emit `ROUND_COMPLETE`, `EXPANSION_PAUSED`, or `CAMPAIGN_COMPLETE` events

**Step 3: Test, verify, commit**

```bash
git commit -m "feat(campaign): add multi-round iterative expansion with safeguards"
```

---

### Task 20: Assets Page — Classification Filter + Triage

**Files:**
- Modify: assets page component (find exact path in dashboard)
- Modify: `dashboard/src/lib/api.ts` (add classification filter param, bulk update endpoint)
- Modify: `orchestrator/main.py` (add asset classification update endpoint)

**Step 1: Add orchestrator endpoint**

```
PUT /api/v1/assets/{asset_id}/classification
Body: { "classification": "in-scope" | "out-of-scope" }

PUT /api/v1/assets/bulk-classification
Body: { "asset_ids": [1, 2, 3], "classification": "in-scope" }
```

**Step 2: Add API client methods**

**Step 3: Update assets page**

- Add `Classification` filter dropdown to filter bar
- `Undetermined` option shows count badge
- Select-all checkbox in table header
- Per-row checkboxes
- Bulk action dropdown: "Set selected → In-scope" | "Set selected → Out-of-scope"
- Per-row action buttons: "Mark In-scope" | "Mark Out-of-scope"
- Marking in-scope triggers pipeline queue (via orchestrator)

**Step 4: Visual verification**

**Step 5: Commit**

```bash
git commit -m "feat(dashboard): add scope classification filter and bulk triage to assets page"
```

---

### Task 21: Assets Page — Association Chain Display

**Files:**
- Modify: assets page component
- Modify: `dashboard/src/lib/api.ts` (add association chain endpoint)

**Step 1: Add orchestrator endpoint**

```
GET /api/v1/assets/{asset_id}/chain
Returns: [{ id, asset_value, asset_type, association_method }, ...]
```

Walks `associated_with_id` chain up to root.

**Step 2: Update assets table**

- Associated assets show link icon + clickable parent text: "Associated with `api.t-mobile.com` via `dns_resolution`"
- Clicking navigates to parent asset detail

**Step 3: Asset detail view**

- Show chain visualization: breadcrumb-style `t-mobile.com → api.t-mobile.com → 52.10.30.40`
- Each node clickable

**Step 4: Visual verification**

**Step 5: Commit**

```bash
git commit -m "feat(dashboard): add association chain display to assets page"
```

---

## Execution Order Summary

| Phase | Tasks | Can ship after |
|-------|-------|---------------|
| **A: Foundation** | 1-5 (DB schema, wildcard engine, scope classifier, deep classifier, pipeline integration) | Independent |
| **B: Tools** | 6-14 (DorkEngine, ArchiveProber, CacheProber, Shodan, Censys, SecurityTrails, pipeline, API keys, dashboard keys) | Phase A |
| **C: Rate Limiting** | 15-18 (core limiter, campaign model, dashboard builder, pipeline integration) | Phase A |
| **D: Expansion + Triage** | 19-21 (multi-round expansion, assets filter/triage, association chains) | Phases A + B |

**Total: 21 tasks across 4 phases.**

Commit after every task. Run full test suite (`pytest tests/ --ignore=tests/e2e --ignore=tests/integration -q`) after each phase to catch regressions.
