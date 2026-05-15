# WSTG-INFO-06 — Identify Application Entry Points: Design

**Date:** 2026-05-15
**Section:** WSTG-INFO-06 (`4.1.6`)
**Worker:** `info_gathering`

## Objective

Implement full OWASP WSTG-INFO-06 coverage in the `info_gathering` pipeline: enumerate every discovered endpoint's parameters, HTTP methods, response headers, cookie-setting behaviour, and WebSocket upgrade capability, and persist the results in structured DB records for downstream workers and `AttackSurfaceAnalyzer`.

---

## Context

Stage 6 (`identify_entry_points`) currently contains three tools:
- `FormMapper` — regex-based HTML form scraping (broken hidden-field extraction, hard-coded URL cap of 20)
- `Paramspider` — archive-crawl parameter discovery; saves URL assets and observations
- `Httpx` — single-host liveness/tech probe on the base domain

Gaps vs. OWASP WSTG-INFO-06:
1. `FormMapper` uses `re.findall` (misses malformed tags, inline attributes, hidden inputs); caps at 20 URLs
2. No WebSocket endpoint detection
3. No per-endpoint response header capture (Set-Cookie, X-*, Server variants)
4. Nothing writes to the `parameters` table — `AttackSurfaceAnalyzer` (Stage 11) reads it but it stays empty
5. `ASSET_TYPES` in `database.py` is missing `"websocket"` and `"url"` despite both being used in practice

**Framework rule:** Never cap URL counts in any tool. Use `rate_limiter` and semaphores for throughput control.

---

## Architecture

Stage 6 is split into two sequential pipeline stages, both under section_id `4.1.6` (consistent with the existing `review_comments` / `review_comments_deep` pattern that share `4.1.5`):

```
Stage("identify_entry_points",  "4.1.6", [FormMapper, Paramspider, Httpx, WebSocketProber])
Stage("aggregate_entry_points", "4.1.6", [EntryPointAggregator])
```

All tools within `identify_entry_points` run concurrently via `asyncio.gather`. `EntryPointAggregator` runs in its own stage so it is guaranteed to read fully committed records from the discovery tools.

`concurrency.py` additions: `WebSocketProber → LIGHT`, `EntryPointAggregator → LIGHT`.

`database.py` addition: `"websocket"` and `"url"` added to `ASSET_TYPES`.

---

## Tool Designs

### 1. Enhanced `FormMapper` (existing, refactored)

**Concurrency:** LIGHT

**Changes from current implementation:**
- Replace `re.findall` form extraction with a stdlib `html.parser` (`HTMLParser` subclass). Handles malformed tags, inline attributes, and CDATA correctly.
- Extract all named inputs per form: `<input>`, `<textarea>`, `<select>`, recording `name`, `type`, and `value` attributes.
- Identify `type="hidden"` inputs explicitly.
- Remove the `urls[:20]` hard cap — process all discovered URL assets.
- Write one `Parameter` record per named input:
  - `asset_id` = the Asset.id of the URL being scanned
  - `param_name` = input name attribute
  - `param_value` = default value (if present), else `None`
  - `source_url` = form action URL (resolved against page URL)
- Write one `Observation` per discovered form:
  - `tech_stack = {_probe: "form_mapper", action, method, input_count, hidden_fields: [list of hidden input names]}`

### 2. `WebSocketProber` (new)

**Concurrency:** LIGHT

**Targets:** base domain + all `subdomain` asset values for the target.

**Path wordlist (13 paths):**
`/ws`, `/socket`, `/websocket`, `/socket.io`, `/chat`, `/live`, `/stream`, `/events`, `/updates`, `/notify`, `/push`, `/realtime`, `/feed`

**Probe behaviour:**
Each probe sends an HTTP GET to `https://{host}{path}` with WS upgrade headers:
```
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: <random 16-byte base64>
```

Response interpretation:
| Status | Meaning | Action |
|--------|---------|--------|
| 101 | WS handshake confirmed | `save_asset(target_id, "websocket", ws_url, "websocket_prober")` + Observation |
| 400 / 403 | Endpoint exists, upgrade rejected | Observation only (`upgrade_rejected: true`), no asset; `asset_id` = existing domain/subdomain Asset for the probed host |
| Other / error | Not a WS endpoint | Skip silently |

**Observation schema (101 case):**
```json
{
  "_probe": "websocket_prober",
  "status": 101,
  "host": "<host>",
  "path": "<path>",
  "upgrade_accepted": true
}
```

**Observation schema (400/403 case):**
```json
{
  "_probe": "websocket_prober",
  "status": 400,
  "host": "<host>",
  "path": "<path>",
  "upgrade_rejected": true
}
```

Returns `{"found": <confirmed_count>, "rejected": <rejected_count>}`.

### 3. `EntryPointAggregator` (new)

**Concurrency:** LIGHT

**Runs in:** `aggregate_entry_points` stage (after `identify_entry_points` completes).

**Phase A — Response header enumeration:**

Reads all `url` and `form` Asset records for the target from DB. For each asset URL (all of them, no cap), rate-limited:
1. Send HEAD request via `aiohttp`. If HEAD returns no useful headers (e.g., 405 Method Not Allowed), retry as GET.
2. Capture: all `Set-Cookie` values, all `X-*` headers, `Server`, `Content-Type`, `Allow`, `WWW-Authenticate`.
3. Infer `auth_required = True` if `WWW-Authenticate` present or status is 401/403.
4. Write `Observation`:
```json
{
  "_probe": "entry_point_aggregator",
  "custom_headers": {"X-Debug": "false", "X-Powered-By": "Express"},
  "set_cookie": ["session=abc; HttpOnly", "csrf=xyz"],
  "auth_required": false,
  "methods_allowed": ["GET", "POST"],
  "status_code": 200
}
```

**Phase B — Parameter consolidation:**

Reads all `url` Asset records created by `Paramspider` (source_tool = `"paramspider"`). For each, parses the query string from `asset_value` and writes a `Parameter` record per query parameter:
- `asset_id` = Asset.id of the paramspider URL
- `param_name` = query param key
- `param_value` = query param value (or `None` if blank)
- `source_url` = full URL

Skips parameters that already have a `Parameter` record for that `(asset_id, param_name)` pair (unique constraint on `parameters` table).

Returns `{"found": <observation_count>, "parameters": <parameter_count>}`.

---

## Data Flow

```
Stages 1–5 complete → url / subdomain / form assets in DB
         │
         ▼
Stage 6a  identify_entry_points  (all tools concurrent)
  FormMapper      → Parameter rows (form inputs) + Observation per form
  Paramspider     → url assets (archive-discovered URLs with params)
  Httpx           → Observation on base domain asset
  WebSocketProber → websocket assets + Observation per confirmed/rejected endpoint
         │
         ▼
Stage 6b  aggregate_entry_points
  EntryPointAggregator
    Phase A: fetch all url/form assets → Observation per endpoint (headers, cookies, auth)
    Phase B: parse Paramspider URLs → Parameter rows (query string params)
         │
         ▼
Stage 7   map_execution_paths  (Katana, Hakrawler)
  — benefits from websocket assets discovered in 6a
Stage 11  map_application  (AttackSurfaceAnalyzer)
  — reads populated parameters table
```

---

## Error Handling

| Tool | Failure mode | Response |
|------|-------------|----------|
| `FormMapper` | Fetch error on a URL | `log.warning`, `continue` to next URL |
| `FormMapper` | Parameter DB write conflict | Unique constraint suppressed (upsert skipped) |
| `WebSocketProber` | Connection error / timeout | Skip silently (expected for non-WS paths) |
| `EntryPointAggregator` | Timeout on HEAD | Retry as GET; if GET also fails, `log.warning` and skip |
| `EntryPointAggregator` | Parameter already exists | Catch `IntegrityError`, skip duplicate silently |

---

## Testing

### `test_form_mapper.py`
- HTML with two forms (one with hidden fields) → assert two `Parameter` sets written, `hidden_fields` present in Observation
- HTML with malformed `<input` tag (no closing `>`) → assert parser does not raise, still finds valid inputs
- Assert no URL cap: seed 30 URL assets, assert all 30 are processed

### `test_websocket_prober.py`
- Mock 101 response for `/ws` → assert `Asset(asset_type="websocket")` created + Observation with `upgrade_accepted: true`
- Mock 403 response for `/websocket` → assert no asset created, Observation with `upgrade_rejected: true`
- Mock connection error → assert no asset, no observation, no exception propagated

### `test_entry_point_aggregator.py`
- Seed two url assets with mock HTTP response returning `Set-Cookie` and `X-Debug` headers → assert two Observations written with correct header data
- Mock 401 response → assert `auth_required: true` in Observation
- Seed Paramspider URL asset with query string `?foo=bar&baz=` → assert two `Parameter` rows written (`foo`/`bar`, `baz`/`None`)
- Seed duplicate parameter → assert `IntegrityError` is swallowed, count unchanged

---

## `pipeline.py` Changes

```python
# Add import
from .tools.websocket_prober import WebSocketProber
from .tools.entry_point_aggregator import EntryPointAggregator

# Replace existing Stage 6 entry
Stage(name="identify_entry_points",  section_id="4.1.6",
      tools=[FormMapper, Paramspider, Httpx, WebSocketProber]),
Stage(name="aggregate_entry_points", section_id="4.1.6",
      tools=[EntryPointAggregator]),
```

## `concurrency.py` Changes

```python
"WebSocketProber":      "LIGHT",
"EntryPointAggregator": "LIGHT",
```

## `database.py` Changes

```python
ASSET_TYPES = (
    "domain", "ip", "subdomain",
    "url",          # added — used by Paramspider and crawlers
    "websocket",    # added — WebSocketProber confirmed WS endpoints
    "sensitive_file", "directory", "error",
    "form", "upload", "deadend", "undetermined",
)
```
