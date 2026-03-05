# Phase 5: Web App Worker — Design Document

**Date:** 2026-03-04
**Phase:** 5 — Web-App-Testing Dockerized Worker
**Spec:** `docs/plans/phase_prompts/phase5.md`

---

## 1. Architecture Overview

The `webapp_worker` follows the same architecture as `recon_core`: a Redis consumer that runs a multi-stage pipeline of tools, with checkpointing and heartbeat support.

```
workers/webapp_worker/
├── __init__.py
├── main.py                  # Redis consumer on webapp_queue
├── pipeline.py              # 6-stage orchestration with checkpointing
├── base_tool.py             # WebAppTool ABC (mirrors ReconTool)
├── browser.py               # Shared Playwright browser manager (singleton)
├── tools/
│   ├── __init__.py
│   │
│   │  # Stage 1: JS Discovery
│   ├── js_crawler.py            # Playwright crawl + JS interception
│   │
│   │  # Stage 2: Static JS Analysis
│   ├── linkfinder.py            # Endpoint extraction from JS
│   ├── jsminer.py               # Hidden endpoints/params
│   ├── mantra.py                # Secrets in JS
│   ├── secretfinder.py          # Sensitive data in JS
│   │
│   │  # Stage 3: Browser Security Audit
│   ├── postmessage.py           # postMessage listener audit
│   ├── dom_sink_analyzer.py     # Sink detection + source tracing
│   ├── storage_auditor.py       # localStorage/sessionStorage/serviceWorker
│   ├── sourcemap_detector.py    # .map file exposure check
│   ├── websocket_analyzer.py    # WS interception + auth check
│   │
│   │  # Stage 4: HTTP Security Analysis
│   ├── header_auditor.py        # CSP/HSTS/X-Frame-Options/X-Content-Type
│   ├── cookie_auditor.py        # Secure/HttpOnly/SameSite flags
│   ├── cors_tester.py           # Origin reflection testing
│   ├── form_analyzer.py         # CSRF tokens + autocomplete
│   │
│   │  # Stage 5: Path & API Discovery
│   ├── sensitive_paths.py       # /.git, /.env, /admin, /debug, /actuator
│   ├── robots_sitemap.py        # robots.txt + sitemap.xml mining
│   ├── graphql_prober.py        # Introspection detection
│   ├── openapi_detector.py      # Swagger/OpenAPI spec discovery
│   ├── open_redirect.py         # Redirect parameter testing
│   │
│   │  # Stage 6: API Endpoint Probing
│   └── newman_prober.py         # Auto-generated Newman collection
```

**Data flow:** Target arrives via `webapp_queue` → load assets with open ports 80/443
from DB → Playwright crawls and saves JS → CLI tools analyze saved JS → Playwright
audits postMessage + DOM sinks + storage → HTTP checks for headers/CORS/cookies/forms
→ path and API discovery → Newman probes discovered endpoints → results written to DB
with scope checks.

---

## 2. Browser Manager (`browser.py`)

Manages a single Playwright Chromium instance shared across Stages 1 and 3.
Semaphore-gated tabs prevent RAM exhaustion.

```python
class BrowserManager:
    """Singleton — one Chromium instance, semaphore-gated tabs."""

    def __init__(self, max_tabs=3, page_timeout=30):
        self._browser = None
        self._playwright = None
        self._semaphore = asyncio.Semaphore(max_tabs)   # from MAX_TABS env
        self._page_timeout = page_timeout * 1000         # Playwright uses ms

    async def start(self):
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
        )

    async def new_page(self, headers=None) -> Page:
        """Acquire semaphore, create page with timeout + optional custom headers."""
        await self._semaphore.acquire()
        page = await self._browser.new_page()
        page.set_default_timeout(self._page_timeout)
        if headers:
            await page.set_extra_http_headers(headers)
        return page

    async def release_page(self, page):
        """Close page and release semaphore slot."""
        await page.close()
        self._semaphore.release()

    async def shutdown(self):
        await self._browser.close()
        await self._playwright.stop()
```

**Key decisions:**
- `MAX_TABS` defaults to 3 (env-configurable) — keeps RAM usage predictable.
- `PAGE_TIMEOUT` defaults to 30s (per spec) — handles heavy SPA apps.
- `--disable-dev-shm-usage` prevents `/dev/shm` exhaustion in Docker.
- Custom headers (auth tokens, user-agents) are injected per-page from `target_profile`.
- Pipeline calls `start()` before Stage 1 and `shutdown()` after Stage 3.

---

## 3. Base Tool (`base_tool.py`)

The `WebAppTool` ABC mirrors `ReconTool` but supports three tool types: CLI, browser,
and HTTP.

```python
class ToolType(Enum):
    CLI = "cli"          # Runs a subprocess (LinkFinder, Mantra, Newman, etc.)
    BROWSER = "browser"  # Uses Playwright (js_crawler, postmessage, dom_sink)
    HTTP = "http"        # Simple HTTP requests (header audit, CORS, paths)

class WebAppTool(ABC):
    name: str
    tool_type: ToolType
    weight_class: WeightClass   # reuse HEAVY/LIGHT from concurrency.py

    @abstractmethod
    async def execute(self, target, scope_manager, **kwargs) -> dict:
        """Returns {"found": N, "in_scope": N, "new": N, "skipped_cooldown": bool}"""

    async def _save_asset(self, session, target_id, url, scope_manager): ...
    async def _save_parameter(self, session, target_id, asset_id, param): ...
    async def _save_vulnerability(self, session, target_id, asset_id, vuln): ...
    async def _save_observation(self, session, target_id, asset_id, obs): ...
    async def _check_cooldown(self, target_id, container_name) -> bool: ...
```

**Differences from `ReconTool`:**
- No `build_command()` / `parse_output()` split — browser and HTTP tools don't run
  subprocesses, so `execute()` is the only abstract method.
- `tool_type` determines how the pipeline provides resources: CLI tools get nothing
  extra, browser tools receive the `BrowserManager`, HTTP tools get an
  `httpx.AsyncClient`.
- Helper methods (`_save_asset`, `_save_vulnerability`, etc.) are concrete — all tools
  share the same scope-check-then-insert logic.
- Cooldown check is a reusable method rather than baked into `execute()`.

The pipeline passes `kwargs` like `browser=BrowserManager` or
`http_client=httpx.AsyncClient` depending on the stage.

---

## 4. Pipeline Stages & Tool Mapping

```python
STAGES = [
    Stage("js_discovery",        [JsCrawler]),
    Stage("static_js_analysis",  [LinkFinder, JsMiner, Mantra, SecretFinder]),
    Stage("browser_security",    [PostMessage, DomSinkAnalyzer, StorageAuditor,
                                  SourcemapDetector, WebSocketAnalyzer]),
    Stage("http_security",       [HeaderAuditor, CookieAuditor, CorsTester,
                                  FormAnalyzer]),
    Stage("path_api_discovery",  [SensitivePaths, RobotsSitemap, GraphqlProber,
                                  OpenApiDetector, OpenRedirect]),
    Stage("api_probing",         [NewmanProber]),
]
```

**Execution logic in `pipeline.run()`:**

1. Load input assets — query `Asset` joined with `Location` where port in (80, 443)
   and state = "open".
2. Load `target.target_profile` for custom headers and scope config.
3. Start `BrowserManager`.
4. For each stage:
   - Check `JobState` for resume (skip completed stages).
   - Update `current_phase` in DB.
   - Inject the right resource via kwargs:
     - Stages 1, 3 → `browser=browser_manager`
     - Stages 4, 5 → `http_client=httpx.AsyncClient` (shared session with custom
       headers)
     - Stages 2, 6 → no extra resource (CLI tools get file paths)
   - Run tools concurrently with `asyncio.gather(..., return_exceptions=True)`.
   - Push `stage_complete` SSE event to `events:{target_id}`.
5. Shut down `BrowserManager` after Stage 3 completes (free RAM for later stages).
6. Mark pipeline complete, push `pipeline_complete` event.

**Stage 1 output feeds everything downstream:**
- JS files saved to `/app/shared/raw/{target_id}/js/`.
- Stage 2 tools read from that directory.
- Discovered URLs are inserted into `assets` table — Stages 3-6 query those.

---

## 5. Tool Details

### Stage 1: JS Discovery

| Tool | Input | Action | Output |
|------|-------|--------|--------|
| `JsCrawler` | Live URLs from DB | Playwright visits each page, intercepts all network responses matching `.js`, saves files to `/app/shared/raw/{target_id}/js/`, extracts inline `<script>` blocks | JS files on disk + new URL assets in DB |

### Stage 2: Static JS Analysis

| Tool | Input | Action | Output |
|------|-------|--------|--------|
| `LinkFinder` | JS files on disk | CLI: `python linkfinder.py -i file.js -o cli` | `assets` (URLs), `parameters` |
| `JsMiner` | JS files on disk | CLI: parses JS for hidden endpoints, API paths, params | `assets` (URLs), `parameters` |
| `Mantra` | JS files on disk | CLI: regex-based secret detection (AWS keys, tokens, passwords) | `vulnerabilities` (severity=critical) + `alerts` |
| `SecretFinder` | JS files on disk | CLI: `python SecretFinder.py -i file.js -o cli` | `vulnerabilities` (severity=critical) + `alerts` |

### Stage 3: Browser Security Audit

| Tool | Input | Action | Output |
|------|-------|--------|--------|
| `PostMessage` | Live URLs | Playwright injects listener on `message` events, checks for missing `event.origin` validation | `vulnerabilities` (severity=high) |
| `DomSinkAnalyzer` | Live URLs + JS files | Regex scan for dangerous DOM sinks (innerHTML, dynamic code execution, timed callbacks), then Playwright traces if URL params/postMessage sources reach those sinks | `vulnerabilities` (severity=high) |
| `StorageAuditor` | Live URLs | Playwright reads `localStorage`, `sessionStorage` keys, flags tokens/PII/API keys | `vulnerabilities` (severity=medium-high) |
| `SourcemapDetector` | JS URLs from Stage 1 | Checks for `.map` suffix on each JS URL, also looks for sourceMappingURL comments | `vulnerabilities` (severity=medium) |
| `WebSocketAnalyzer` | Live URLs | Playwright intercepts WS connections, checks if upgrade includes auth, logs message patterns | `observations` + `vulnerabilities` if no auth |

### Stage 4: HTTP Security Analysis

| Tool | Input | Action | Output |
|------|-------|--------|--------|
| `HeaderAuditor` | Live URLs | httpx GET, checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | `observations` (headers in JSONB) + `vulnerabilities` for missing critical headers |
| `CookieAuditor` | Live URLs | httpx GET, inspects `Set-Cookie` for `Secure`, `HttpOnly`, `SameSite` flags | `vulnerabilities` (severity=medium) |
| `CorsTester` | Live URLs | httpx with `Origin: https://attacker.com` header, checks if reflected in `Access-Control-Allow-Origin` | `vulnerabilities` (severity=high) |
| `FormAnalyzer` | Live URLs | httpx GET, parse HTML for `<form>` tags, check for CSRF tokens and `autocomplete` on sensitive fields | `vulnerabilities` (severity=medium) |

### Stage 5: Path & API Discovery

| Tool | Input | Action | Output |
|------|-------|--------|--------|
| `SensitivePaths` | Base URLs | httpx probes wordlist of paths (`/.git/HEAD`, `/.env`, `/admin`, `/debug`, `/actuator/health`) | `vulnerabilities` (severity=critical for .env/.git) + `assets` |
| `RobotsSitemap` | Base URLs | Fetch `/robots.txt` + `/sitemap.xml`, extract paths | `assets` (URLs) |
| `GraphqlProber` | Base URLs | httpx POST introspection query to common GraphQL paths (`/graphql`, `/api/graphql`) | `vulnerabilities` if introspection enabled + `observations` |
| `OpenApiDetector` | Base URLs | httpx probes `/swagger.json`, `/api-docs`, `/openapi.json`, `/v1/api-docs` | `assets` (URLs) + `observations` |
| `OpenRedirect` | URLs with params from DB | httpx with redirect param set to `https://attacker.com`, checks `Location` header | `vulnerabilities` (severity=medium) |

### Stage 6: API Endpoint Probing

| Tool | Input | Action | Output |
|------|-------|--------|--------|
| `NewmanProber` | All discovered endpoints from Stages 2+5 | Generates Postman collection JSON, runs `newman run` with method enumeration (GET/POST/PUT/DELETE), checks for auth bypass, verbose errors, sensitive data | `vulnerabilities` + `observations` |

---

## 6. Dockerfile & Docker Compose

### Dockerfile (`docker/Dockerfile.webapp`)

Three-stage build:

```dockerfile
# Stage 1: Node.js tools
FROM node:20-slim AS node-builder
RUN npm install -g @nicedoc/linkfinder newman

# Stage 2: Python tools
FROM python:3.10-slim-bookworm AS py-builder
RUN pip install --target=/py-tools \
    secretfinder mantra jsminer httpx[http2] beautifulsoup4

# Stage 3: Runtime
FROM python:3.10-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm chromium libglib2.0-0 libnss3 libatk1.0-0 \
    libatk-bridge2.0-0 libcups2 libdrm2 libxcomposite1 \
    libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libxshmfence1 gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install playwright && \
    PLAYWRIGHT_BROWSERS_PATH=/usr/lib/playwright \
    playwright install chromium

COPY --from=node-builder /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=node-builder /usr/local/bin/newman /usr/local/bin/
COPY --from=py-builder /py-tools /usr/local/lib/python3.10/site-packages/

COPY shared/lib_webbh /app/shared/lib_webbh
RUN pip install /app/shared/lib_webbh
RUN mkdir -p /app/shared/raw /app/shared/config /app/shared/logs
COPY workers/__init__.py /app/workers/__init__.py
COPY workers/webapp_worker /app/workers/webapp_worker

RUN python -c "from workers.webapp_worker.main import main; print('webapp-worker OK')"

ENTRYPOINT ["python", "-m", "workers.webapp_worker.main"]
```

### Docker Compose addition

```yaml
webapp-worker:
  build:
    context: .
    dockerfile: docker/Dockerfile.webapp
  container_name: webbh-webapp-worker
  restart: unless-stopped
  depends_on:
    postgres: { condition: service_healthy }
    redis: { condition: service_healthy }
  environment:
    DB_HOST: postgres
    DB_PORT: "5432"
    DB_NAME: ${DB_NAME:-webbh}
    DB_USER: ${DB_USER:-webbh_admin}
    DB_PASS: ${DB_PASS:-changeme}
    REDIS_HOST: redis
    REDIS_PORT: "6379"
    MAX_TABS: "3"
    PAGE_TIMEOUT: "30"
  volumes:
    - ./shared:/app/shared
  networks:
    - webbh-net
```

**Note:** Exact Python package names for mantra/secretfinder/jsminer/linkfinder will
need verification during implementation — some may be GitHub-only installs
(`pip install git+https://...`).

---

## 7. Error Handling, Cooldowns & Testing

### Error handling per tool type

- **CLI tools** — same as recon_core: `asyncio.TimeoutError` and `FileNotFoundError`
  caught in `execute()`, logged and skipped gracefully. Tool returns
  `{"found": 0, "error": "timeout"}`.
- **Browser tools** — Playwright-specific errors: `TimeoutError` (page didn't load in
  30s), `net::ERR_CONNECTION_REFUSED`, page crashes. All caught per-page, logged, page
  released back to `BrowserManager`. One failing URL doesn't kill the stage.
- **HTTP tools** — `httpx.TimeoutException`, `httpx.ConnectError` caught per-URL.
  Connection pool shared across Stages 4-5 via a single
  `httpx.AsyncClient(timeout=15, limits=Limits(max_connections=10))`.
- **Pipeline level** — `asyncio.gather(..., return_exceptions=True)` same as recon_core.
  Failed tools don't block stage completion. Pipeline marks `FAILED` in `JobState` only
  if an unrecoverable error occurs (e.g., no input assets found).

### Cooldown

- Same 24-hour cooldown as recon_core, keyed on
  `(target_id, container_name, tool_name)`.
- `JsCrawler` cooldown is checked first — if JS files already exist from a recent run,
  Stage 2 tools can reuse them without re-crawling.

### Testing strategy

- **Unit tests** mock `BrowserManager` — return fake pages with pre-built DOM.
- **CLI tools** mock `subprocess` same as recon_core tests.
- **HTTP tools** mock `httpx.AsyncClient` responses.
- **Pipeline test** verifies stage ordering and resume logic (same pattern as
  `test_recon_pipeline.py`).
- **Integration test** mocks all externals, verifies end-to-end flow from
  `webapp_queue` message to DB writes.
- Test files: `tests/test_webapp_pipeline.py` + `tests/test_webapp_tools.py`.

---

## 8. DB Tables Used

| Model | Read/Write | Purpose |
|-------|-----------|---------|
| `Target` | Read | Load target profile, scope config, custom headers |
| `Asset` | Read + Write | Input: live domains with HTTP ports. Output: discovered URLs |
| `Location` | Read | Filter assets with port 80/443 open |
| `Observation` | Write | HTTP headers, tech stack, page metadata |
| `Parameter` | Write | Extracted params from JS |
| `Vulnerability` | Write | XSS, secrets, misconfigs, exposed paths |
| `Alert` | Write | Critical findings (secrets, .env/.git exposure) |
| `JobState` | Read + Write | Checkpointing, cooldown, heartbeat |

## 9. Integration Points

- **Queue:** Listens on `webapp_queue` / `webapp_group`, consumer from `HOSTNAME` env.
- **Trigger:** Already wired in `event_engine._check_web_trigger()` for ports 80/443.
- **Container naming:** `webbh-webapp_testing-t{target_id}` (set by event_engine).
- **SSE events:** Pushes to `events:{target_id}` for dashboard updates.
- **Image config:** `WORKER_IMAGE_WEBAPP` env var already defined in orchestrator.

## 10. Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Tool overlap | Run all, deduplicate at DB layer | Maximum detection coverage |
| JS discovery | Playwright crawl, offline analysis | Clean separation, one browser session |
| DOM XSS depth | Static sink detection + passive validation | Safe, no WAF triggers |
| Browser concurrency | Single browser, semaphore-gated tabs | RAM predictability |
| Stage count | 6 stages | Grouped by operation type (browser/CLI/HTTP) |
| Postman integration | Newman CLI, auto-generated collections | API endpoint probing from discovered endpoints |
