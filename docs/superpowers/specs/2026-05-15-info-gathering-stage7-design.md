# Info Gathering Stage 7 — Map Execution Paths (WSTG-INFO-07)

**Status:** design
**Date:** 2026-05-15
**Owner:** info_gathering worker
**OWASP reference:** [WSTG-INFO-07 — Map Execution Paths Through Application](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application)

---

## 1. Goals, scope, and inputs

Stage 7 maps the execution paths of the target application by combining deep web crawling (Katana + Hakrawler) with an in-process post-crawl path analyzer that categorizes discovered URLs into structured execution path buckets. This gives downstream workers (`reasoning_worker`, `chain_worker`) a structured picture of the application's surface: auth flows, API endpoints, admin panels, WebSocket endpoints, file download paths, and more.

### 1.1 What Stage 7 does NOT do

- Emit Vulnerabilities — analysis is purely observational; vulnerability judgement is delegated to `reasoning_worker`.
- Replace Stage 4 subdomain enumeration or Stage 6 entry-point discovery — Stage 7 consumes their output as crawl seeds.
- Perform active fuzzing, parameter manipulation, or authentication testing.

### 1.2 Inputs (passed via `tool.execute(**kwargs)`)

- `target_id: int`
- `asset_id: int` — resolved by the pipeline preamble (subject Asset for this host)
- `host: str` — the literal `Asset.asset_value` being crawled (not always `base_domain`)
- `intensity: Literal["low","medium","high"]` — controls crawl depth and request rate
- `scope_manager` — used to filter discovered URLs before saving
- `headers: dict | None` — custom headers forwarded to crawlers
- `rate_limiter` — pipeline-wide rate limit token bucket

### 1.3 Outputs

1. `Asset` rows for every in-scope URL discovered (saved during crawl, deduplicated by the existing `uq_assets_target_type_value` constraint).
2. One summary `Observation` row with `tech_stack._probe = "execution_paths"` — the categorized path map.
3. Standard `STAGE_COMPLETE` SSE event on `events:{target_id}` with `stats.paths_found`.

---

## 2. Architecture and data flow

Stage 7 follows the Stage 2 pattern exactly: tools run via `asyncio.gather`, each returning a `CrawlResult` dataclass, and a post-gather hook in `pipeline.run()` invokes `ExecutionPathAnalyzer` with the in-memory results — no extra DB round-trip.

```
pipeline.run()
  │
  ├─ [pre-Stage 7] _fetch_ws_seeds(target_id)
  │     → query Asset WHERE asset_type="websocket" AND target_id=N
  │     → list[str] of wss:// / ws:// URLs from Stage 6 + prior crawls
  │
  ├─ asyncio.gather(
  │    Katana.execute(host, asset_id, intensity, ws_seeds, scope_manager,
  │                   headers, rate_limiter, ...)  → CrawlResult
  │    Hakrawler.execute(host, asset_id, intensity, scope_manager,
  │                      headers, rate_limiter, ...) → CrawlResult
  │  )
  │
  └─ [post-Stage 7 hook] ExecutionPathAnalyzer(
         crawl_results=[CrawlResult, CrawlResult],
         asset_id=N, target_id=N, intensity=intensity
       ).write_summary()
           → writes 1 Observation (_probe="execution_paths")
```

### 2.1 CrawlResult dataclass

```python
@dataclass
class CrawlResult:
    tool: str           # "katana" | "hakrawler"
    urls: list[str]     # all discovered in-scope URLs (already saved as Asset rows)
    ws_urls: list[str]  # ws:// / wss:// URLs found during this crawl
    error: str | None   # set if the tool failed; analyzer marks summary partial
```

---

## 3. Tool design

### 3.1 Katana rewrite

Katana is rewritten from scratch as a pipeline-aware tool. Key behaviours:

**WebSocket seed feed** — before building the command, queries DB for `asset_type="websocket"` assets under `target_id`. Each WS URL is added as an additional `-u` seed alongside `host`.

**Intensity → flags:**

| Intensity | `-d` depth | Additional flags |
|-----------|-----------|-----------------|
| `low` | 2 | `-js-crawl -form-extraction -passive` |
| `medium` | 3 | `-js-crawl -form-extraction -passive` |
| `high` | 5 | `-js-crawl -form-extraction -passive` |

JS rendering (`-js-crawl`), form-follow (`-form-extraction`), and passive JS execution (`-passive`) run at all intensity levels. Only crawl depth and request rate vary.

**Headers** — each key/value in the `headers` dict is passed as `-H "Key: Value"`.

**Scope enforcement** — every discovered URL is passed through `scope_manager.classify()` before `save_asset`. Out-of-scope URLs are silently dropped.

**Asset type classification** — `url_classifier.classify_url()` is called on each URL. `ws://`/`wss://` URLs are saved as `asset_type="websocket"`.

**Return value** — `CrawlResult(tool="katana", urls=[...], ws_urls=[...], error=None)`. On subprocess failure, returns `CrawlResult(tool="katana", urls=[], ws_urls=[], error=str(e))`.

### 3.2 Hakrawler rewrite

Same pattern as Katana, simpler flags:

- `-depth` mapped from intensity (2 / 3 / 5)
- Headers passed via `-h "Key: Value"` flags
- Scope-checked per URL; returns `CrawlResult`
- No JS rendering (Hakrawler is a pure HTTP crawler — Katana handles JS)

### 3.3 Intensity → request rate

Request rate is enforced by the existing pipeline `rate_limiter` token bucket — no new machinery:

| Intensity | Effective req/sec |
|-----------|------------------|
| `low` | 1 |
| `medium` | 2 |
| `high` | 4 |

### 3.4 No URL caps

Neither tool imposes a URL cap. The pipeline processes every in-scope URL the crawlers return. This is a deliberate design decision — the `uq_assets_target_type_value` DB constraint handles deduplication at the storage layer.

---

## 4. ExecutionPathAnalyzer

Runs in-process after `asyncio.gather` completes. Consumes the `CrawlResult` list directly — no DB read.

### 4.1 Categorization buckets (applied in priority order)

| Category | Match patterns |
|----------|---------------|
| `websocket` | `ws://`, `wss://` |
| `api_endpoint` | `/api/`, `/v1/`, `/v2/`, `/v3/`, `/graphql`, `/rest/`, `/rpc`, `.json`, `.xml` |
| `auth_flow` | `/login`, `/logout`, `/auth`, `/oauth`, `/signin`, `/signup`, `/register`, `/password`, `/forgot`, `/reset`, `/sso`, `/saml` |
| `admin_panel` | `/admin`, `/administrator`, `/management`, `/manage`, `/control`, `/cms`, `/wp-admin`, `/cpanel` |
| `file_download` | `.pdf`, `.zip`, `.csv`, `.xlsx`, `.docx`, `.tar`, `.gz` |
| `static_asset` | `.js`, `.css`, `.png`, `.jpg`, `.svg`, `.woff`, `.ttf`, `.ico` |
| `error_page` | `/error`, `/404`, `/500`, `traceback`, `exception` |
| `other` | all remaining URLs |

Each URL matches exactly one category — the first matching bucket wins.

### 4.2 Summary Observation payload (`tech_stack` field)

```json
{
  "_probe": "execution_paths",
  "intensity": "medium",
  "depth": 3,
  "total_paths": 423,
  "ws_seeds_used": ["wss://example.com/ws"],
  "categories": {
    "websocket":      ["wss://example.com/ws"],
    "api_endpoint":   ["https://example.com/api/v1/users", "..."],
    "auth_flow":      ["https://example.com/login", "..."],
    "admin_panel":    [],
    "file_download":  [],
    "static_asset":   ["..."],
    "error_page":     [],
    "other":          ["..."]
  },
  "tool_breakdown": {
    "katana":    {"total": 310, "errored": false},
    "hakrawler": {"total": 113, "errored": false}
  }
}
```

### 4.3 Failure tolerance

If both crawlers errored, the summary is still written with `"partial": true` and zero-length category lists. If one errored, `tool_breakdown` reflects it and `partial: true` is set. This mirrors Stage 2's aggregator behaviour.

---

## 5. Cross-cutting changes

### 5.1 `url_classifier.py` additions

```python
# WebSocket URLs — checked before any path-based rules
if url.startswith(("ws://", "wss://")):
    return "websocket"

# API endpoint patterns
_API_PATTERNS = frozenset({
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc"
})
# checked after sensitive_file and directory, before error
```

### 5.2 `database.py` — ASSET_TYPES additions

```python
ASSET_TYPES = (
    ...,
    "websocket",      # ws:// / wss:// endpoints
    "api_endpoint",   # REST / GraphQL / RPC paths
)
```

No Alembic migration required — `ASSET_TYPES` is a Python tuple used for documentation and validation, not a Postgres enum.

### 5.3 Global URL cap removal

| File | Change |
|------|--------|
| `workers/info_gathering/tools/form_mapper.py` | Remove `urls[:20]` slice |

A grep for `[:\d+]` slice patterns on URL/asset lists will be performed during implementation to catch any other caps.

---

## 6. Pipeline plumbing

Two additions to `pipeline.run()` in the main stage loop:

```python
# Pre-Stage 7: fetch WebSocket seeds
ws_seeds: list[str] = []
if stage.section_id == "4.1.7":
    ws_seeds = await self._fetch_ws_seeds(self.target_id)

results = await self._run_stage(
    stage, ..., ws_seeds=ws_seeds, ...
)

# Post-Stage 7: invoke path analyzer
if stage.section_id == "4.1.7":
    from workers.info_gathering.tools.execution_path_analyzer import (
        ExecutionPathAnalyzer, CrawlResult,
    )
    analyzer = ExecutionPathAnalyzer(asset_id=asset_id, target_id=self.target_id)
    crawl_results = [r for r in results if isinstance(r, CrawlResult)]
    summary_obs_id = await analyzer.write_summary(crawl_results, intensity=intensity)
    stats["paths_found"] = sum(len(r.urls) for r in crawl_results if r.error is None)
    stats["summary_written"] = summary_obs_id is not None
```

`_fetch_ws_seeds` is a single `get_session` query:

```python
async def _fetch_ws_seeds(self, target_id: int) -> list[str]:
    async with get_session() as session:
        stmt = select(Asset.asset_value).where(
            Asset.target_id == target_id,
            Asset.asset_type == "websocket",
        )
        result = await session.execute(stmt)
        return [row[0] for row in result.all()]
```

`ws_seeds` is forwarded through `_run_stage` into each tool's `execute(**kwargs)`.

---

## 7. File changes

### New files

```
workers/info_gathering/tools/execution_path_analyzer.py
tests/test_info_gathering_stage7.py
tests/test_info_gathering_stage7_integration.py
```

### Modified files

| File | Change |
|------|--------|
| `workers/info_gathering/tools/katana.py` | Full rewrite — pipeline-aware, WS seeds, intensity flags, headers, scope check, returns `CrawlResult` |
| `workers/info_gathering/tools/hakrawler.py` | Full rewrite — pipeline-aware, intensity depth, headers, scope check, returns `CrawlResult` |
| `workers/info_gathering/tools/url_classifier.py` | Add `websocket` and `api_endpoint` classifications |
| `workers/info_gathering/tools/form_mapper.py` | Remove `urls[:20]` URL cap |
| `workers/info_gathering/pipeline.py` | Add `_fetch_ws_seeds`; add Stage 7 pre/post hooks in `run()`; forward `ws_seeds` through `_run_stage` into `tool.execute(**kwargs)` |
| `shared/lib_webbh/database.py` | Add `"websocket"`, `"api_endpoint"` to `ASSET_TYPES` |

---

## 8. Test plan

### 8.1 Unit tests (`tests/test_info_gathering_stage7.py`)

1. `test_katana_uses_host_not_base_domain`
2. `test_katana_intensity_low_sets_depth_2`
3. `test_katana_intensity_high_sets_depth_5`
4. `test_katana_feeds_ws_seeds_as_additional_urls`
5. `test_katana_scope_check_filters_out_of_scope_urls`
6. `test_katana_saves_ws_url_as_websocket_asset_type`
7. `test_katana_returns_crawl_result`
8. `test_katana_headers_forwarded_as_H_flags`
9. `test_hakrawler_uses_host_not_base_domain`
10. `test_hakrawler_returns_crawl_result`
11. `test_hakrawler_intensity_medium_sets_depth_3`
12. `test_url_classifier_ws_prefix_returns_websocket`
13. `test_url_classifier_wss_prefix_returns_websocket`
14. `test_url_classifier_api_path_returns_api_endpoint`
15. `test_analyzer_categorizes_auth_flow_urls`
16. `test_analyzer_categorizes_admin_panel_urls`
17. `test_analyzer_categorizes_api_endpoint_urls`
18. `test_analyzer_writes_summary_observation_with_correct_asset_id`
19. `test_analyzer_partial_true_when_both_crawlers_error`
20. `test_analyzer_partial_true_when_one_crawler_errors`
21. `test_analyzer_tool_breakdown_reflects_per_tool_counts`
22. `test_analyzer_first_matching_bucket_wins`

### 8.2 Integration tests (`tests/test_info_gathering_stage7_integration.py`)

| # | Test | What it proves |
|---|------|----------------|
| I1 | `test_stage7_full_path_writes_summary_observation` | Crawl → analyzer → 1 summary Observation with correct `asset_id` |
| I2 | `test_stage7_ws_seeds_queried_and_passed_to_katana` | WS asset in DB → Katana cmd contains the `wss://` seed URL |
| I3 | `test_stage7_scope_violations_not_saved` | Out-of-scope URL → no Asset row written |
| I4 | `test_stage7_sse_event_includes_paths_found` | `STAGE_COMPLETE` event has `stats.paths_found` |
| I5 | `test_stage7_intensity_medium_depth_3_in_katana_cmd` | Medium intensity → `-d 3` in Katana subprocess args |
| I6 | `test_stage7_partial_summary_when_hakrawler_fails` | Hakrawler timeout → summary has `partial:true`, Katana results preserved |
| I7 | `test_stage7_ws_urls_saved_as_websocket_asset_type` | Crawl surfaces `wss://` URL → `asset_type="websocket"` in DB |
| I8 | `test_stage7_no_url_cap_on_form_mapper` | FormMapper processes more than 20 URLs |
| I9 | `test_stage7_headers_passed_to_katana` | `headers={"Cookie": "..."}` → `-H Cookie:...` in Katana cmd |
| I10 | `test_stage7_dedup_does_not_create_duplicate_assets` | Same URL from both crawlers → single Asset row |
