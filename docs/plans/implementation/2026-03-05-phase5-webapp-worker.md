# Phase 5: Web App Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the webapp_worker — a Dockerized headless-browser worker that analyzes web applications across 6 stages: JS discovery, static JS analysis, browser security audit, HTTP security analysis, path/API discovery, and API endpoint probing.

**Architecture:** Mirrors recon_core — Redis consumer -> 6-stage pipeline -> tool ABC -> individual tools. New BrowserManager module manages a shared Playwright Chromium instance with semaphore-gated tabs. Three tool types: CLI (subprocess), BROWSER (Playwright), HTTP (httpx).

**Tech Stack:** Python 3.10+, Playwright (async), httpx, Newman (Postman CLI), SQLAlchemy async, Redis Streams, lib_webbh shared library.

**Design doc:** docs/plans/design/2026-03-04-phase5-webapp-worker-design.md

---

## Task 1: Package Scaffolding

**Files:**
- Create: workers/webapp_worker/__init__.py
- Create: workers/webapp_worker/concurrency.py
- Create: tests/test_webapp_pipeline.py (starter)

**Step 1: Create package directory and __init__.py**

Empty file — package marker only.

**Step 2: Create concurrency.py**

Copy from workers/recon_core/concurrency.py since each worker runs in its own container and cannot import across workers. Contains WeightClass enum and get_semaphore() function.

**Step 3: Create test starter**

tests/test_webapp_pipeline.py with:
- os.environ.setdefault for DB_DRIVER and DB_NAME
- import pytest

**Step 4: Commit**

git commit -m "feat(webapp-worker): scaffold package with concurrency module"

---

## Task 2: Browser Manager

**Files:**
- Create: workers/webapp_worker/browser.py
- Modify: tests/test_webapp_pipeline.py

**Step 1: Write the failing tests**

Three tests:
1. test_browser_manager_new_page_acquires_semaphore - verify semaphore count decrements
2. test_browser_manager_release_page_frees_semaphore - verify semaphore count increments
3. test_browser_manager_injects_custom_headers - verify set_extra_http_headers called

All tests mock _browser (no real Playwright needed).

**Step 2: Run test to verify it fails**

Run: python -m pytest tests/test_webapp_pipeline.py -v -k "browser_manager"
Expected: FAIL — ModuleNotFoundError

**Step 3: Write the implementation**

workers/webapp_worker/browser.py — BrowserManager class with:
- __init__(max_tabs, page_timeout): creates Semaphore and stores timeout in ms
- start(): launches Playwright chromium with --no-sandbox, --disable-gpu, --disable-dev-shm-usage
- new_page(headers): acquires semaphore, creates page, sets timeout, optionally sets extra HTTP headers
- release_page(page): closes page in try/finally, releases semaphore
- shutdown(): closes browser and playwright

Lazy import of playwright.async_api inside start() so tests don't need Playwright installed.

Env vars: MAX_TABS (default 3), PAGE_TIMEOUT (default 30).

**Step 4: Run test to verify it passes**

Expected: 3 passed

**Step 5: Commit**

git commit -m "feat(webapp-worker): add BrowserManager with semaphore-gated tabs"

---

## Task 3: WebAppTool Base Class

**Files:**
- Create: workers/webapp_worker/base_tool.py
- Modify: tests/test_webapp_pipeline.py

**Step 1: Write the failing tests**

Two tests:
1. test_base_tool_check_cooldown_returns_false_when_no_job - create in-memory DB, verify cooldown returns False when no matching JobState exists
2. test_base_tool_save_vulnerability_creates_alert_for_critical - seed Target + Asset, call _save_vulnerability with severity="critical", verify Alert row created

Both tests create tables via Base.metadata.create_all on sqlite.

**Step 2: Run test to verify it fails**

Expected: FAIL — ModuleNotFoundError

**Step 3: Write the implementation**

workers/webapp_worker/base_tool.py containing:

ToolType enum: CLI, BROWSER, HTTP

WebAppTool ABC with:
- Class attrs: name, tool_type, weight_class
- Abstract method: execute(target, scope_manager, target_id, container_name, headers, **kwargs) -> dict
- check_cooldown(target_id, container_name): queries JobState for COMPLETED with matching last_tool_executed within COOLDOWN_HOURS
- update_tool_state(target_id, container_name): updates JobState.last_tool_executed
- run_subprocess(cmd, timeout): asyncio.create_subprocess with timeout, returns stdout string
- _get_live_urls(target_id): joins Asset+Location where port in (80,443) and state=open, returns [(asset_id, domain)]
- _save_asset(target_id, url, scope_manager): scope check, upsert Asset, returns asset_id or None
- _save_parameter(asset_id, param_name, param_value, source_url): dedup insert Parameter
- _save_vulnerability(target_id, asset_id, severity, title, description, poc): insert Vulnerability, call _create_alert if severity in (critical, high)
- _save_observation(asset_id, status_code, page_title, tech_stack, headers): insert Observation
- _create_alert(target_id, vuln_id, message): insert Alert + push_task SSE event

Env vars: TOOL_TIMEOUT (default 600), COOLDOWN_HOURS (default 24).

**Step 4: Run test to verify it passes**

Expected: 2 passed

**Step 5: Commit**

git commit -m "feat(webapp-worker): add WebAppTool ABC with DB helpers"

---

## Task 4: Pipeline

**Files:**
- Create: workers/webapp_worker/pipeline.py
- Modify: tests/test_webapp_pipeline.py

**Step 1: Write the failing tests**

Four tests:
1. test_webapp_stages_defined_in_order - verify 6 stages with correct names (SKIP until Task 16)
2. test_webapp_each_stage_has_tools - verify each stage has >0 tools (SKIP until Task 16)
3. test_webapp_stage_tools_are_webapp_tool_subclasses (SKIP until Task 16)
4. test_webapp_pipeline_skips_completed_stages - mock _get_completed_phase returning "static_js_analysis", verify _run_stage called 4 times with correct stage names

**Step 2: Run test to verify it fails**

Expected: FAIL

**Step 3: Write the implementation**

workers/webapp_worker/pipeline.py containing:

Constants:
- BROWSER_STAGES = {"js_discovery", "browser_security"}
- HTTP_STAGES = {"http_security", "path_api_discovery"}

Stage dataclass: name + tool_classes list
STAGES list: initially empty, populated in Task 16
STAGE_INDEX: dict rebuilt by _rebuild_index()

Pipeline class with:
- __init__(target_id, container_name)
- run(target, scope_manager, headers):
  1. _rebuild_index()
  2. _get_completed_phase() for resume
  3. Loop STAGES from start_index:
     - _update_phase(stage.name)
     - _manage_browser() — start BrowserManager if stage in BROWSER_STAGES
     - Build kwargs: browser for BROWSER_STAGES, http_client for HTTP_STAGES
     - _run_stage(stage, target, scope_manager, headers, **kwargs)
     - push_task SSE stage_complete event
     - Shutdown browser after "browser_security" stage
  4. _mark_completed() + push_task pipeline_complete
- _manage_browser(stage_name, browser_mgr): start BrowserManager if needed
- _get_http_client(headers): create httpx.AsyncClient(timeout=15, max_connections=10)
- _run_stage(): instantiate tools, asyncio.gather with return_exceptions, aggregate stats, close http_client
- _get_completed_phase(): query JobState COMPLETED
- _update_phase(phase): update JobState.current_phase
- _mark_completed(): set JobState.status = COMPLETED

**Step 4: Run test to verify it passes**

Expected: Non-skipped tests pass

**Step 5: Commit**

git commit -m "feat(webapp-worker): add 6-stage pipeline with browser lifecycle"

---

## Task 5: Entry Point (main.py)

**Files:**
- Create: workers/webapp_worker/main.py

**Step 1: Write the implementation**

Mirrors workers/recon_core/main.py exactly, with these changes:
- Logger name: "webapp-worker"
- Queue: "webapp_queue" / "webapp_group"
- Default action: "webapp_testing"
- Imports Pipeline from workers.webapp_worker.pipeline
- Container name fallback: "webapp-worker-unknown"

Same handle_message flow: load Target, create ScopeManager, ensure JobState row, create Pipeline, run with heartbeat, mark FAILED on exception.

**Step 2: Commit**

git commit -m "feat(webapp-worker): add main entry point with Redis listener"

---

## Task 6: Stage 1 — JsCrawler

**Files:**
- Create: workers/webapp_worker/tools/__init__.py (empty)
- Create: workers/webapp_worker/tools/js_crawler.py
- Create: tests/test_webapp_tools.py

**Step 1: Write the failing test**

test_js_crawler_saves_js_files:
- Mock BrowserManager (new_page returns AsyncMock page, release_page is AsyncMock)
- Mock page.goto, page.evaluate (returns ["var x = 1;"])
- Patch _get_live_urls to return [(1, "example.com")]
- Patch check_cooldown, update_tool_state, _save_asset
- Use tmp_path for JS_DIR
- Verify browser.new_page called, browser.release_page called, result not skipped

**Step 2: Run test — expected FAIL**

**Step 3: Write implementation**

JsCrawler(WebAppTool):
- name="js_crawler", tool_type=BROWSER, weight_class=HEAVY
- execute(): cooldown check, get BrowserManager from kwargs, get_live_urls
- For each (asset_id, domain): try https then http
  - new_page with headers
  - Register page.on("response") handler: if URL ends .js or content-type has javascript, save to /app/shared/raw/{target_id}/js/
  - page.goto with wait_until="networkidle"
  - page.evaluate to extract inline script textContent
  - Save inline scripts to files
  - _save_asset for each JS URL
  - release_page in finally block
- update_tool_state, return stats

**Step 4: Run test — expected PASS**

**Step 5: Commit**

git commit -m "feat(webapp-worker): add JsCrawler tool (Stage 1)"

---

## Task 7: Stage 2 — LinkFinder + JsMiner

**Files:**
- Create: workers/webapp_worker/tools/linkfinder.py
- Create: workers/webapp_worker/tools/jsminer.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_linkfinder_parses_endpoints: call parse_output with sample stdout, verify 3 endpoints returned
2. test_jsminer_parses_endpoints: call parse_output with JSON array stdout, verify 2 endpoints returned

**Step 2: Run test — expected FAIL**

**Step 3: Write LinkFinder**

LinkFinder(WebAppTool):
- name="linkfinder", tool_type=CLI, weight_class=LIGHT
- parse_output(stdout): split lines, strip, filter empty/bracket lines
- execute(): cooldown check, glob JS files from /app/shared/raw/{target_id}/js/
- For each JS file: run_subprocess ["python3", "-m", "linkfinder", "-i", file, "-o", "cli"]
- Parse endpoints, build full URLs with target.base_domain prefix
- _save_asset for each, extract URL params with urlparse/parse_qs, _save_parameter
- update_tool_state, return stats

**Step 4: Write JsMiner**

JsMiner(WebAppTool):
- name="jsminer", tool_type=CLI, weight_class=LIGHT
- parse_output(stdout): try JSON array parse, fallback to line-by-line
- execute(): same pattern as LinkFinder but runs ["jsminer", "-f", filepath]

**Step 5: Run tests — expected PASS**

**Step 6: Commit**

git commit -m "feat(webapp-worker): add LinkFinder and JsMiner tools (Stage 2)"

---

## Task 8: Stage 2 — Mantra + SecretFinder

**Files:**
- Create: workers/webapp_worker/tools/mantra.py
- Create: workers/webapp_worker/tools/secretfinder.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_mantra_parses_secrets: parse JSON-per-line stdout, verify type and match fields
2. test_secretfinder_parses_secrets: parse line-per-finding stdout, verify count

**Step 2: Run test — expected FAIL**

**Step 3: Write Mantra**

Mantra(WebAppTool):
- name="mantra", tool_type=CLI, weight_class=LIGHT
- parse_output(stdout): JSON-per-line parsing -> list[dict]
- execute(): glob JS files, run ["mantra", "-f", filepath]
- For each secret found: _save_vulnerability with severity=critical, title includes secret type and filename
- update_tool_state, return stats

**Step 4: Write SecretFinder**

SecretFinder(WebAppTool):
- name="secretfinder", tool_type=CLI, weight_class=LIGHT
- parse_output(stdout): line-per-finding -> list[str]
- execute(): glob JS files, run ["python3", "SecretFinder.py", "-i", filepath, "-o", "cli"]
- For each finding: _save_vulnerability with severity=critical
- update_tool_state, return stats

**Step 5: Run tests — expected PASS**

**Step 6: Commit**

git commit -m "feat(webapp-worker): add Mantra and SecretFinder tools (Stage 2)"

---

## Task 9: Stage 3 — PostMessage + DomSinkAnalyzer

**Files:**
- Create: workers/webapp_worker/tools/postmessage.py
- Create: workers/webapp_worker/tools/dom_sink_analyzer.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_postmessage_detects_insecure_listener:
   - Mock page.evaluate returning [{has_origin_check: False, handler_preview: "..."}]
   - Verify _save_vulnerability called

2. test_dom_sink_analyzer_detects_sinks:
   - Call _find_sinks with JS containing innerHTML and setTimeout patterns
   - Verify at least 1 sink found with "innerHTML" in description

**Step 2: Run test — expected FAIL**

**Step 3: Write PostMessage**

PostMessage(WebAppTool):
- name="postmessage", tool_type=BROWSER, weight_class=HEAVY
- Contains HOOK_SCRIPT constant: JS that hooks EventTarget.addEventListener("message"),
  checks handler source for origin validation patterns, returns array of {has_origin_check, handler_preview}
- execute(): get BrowserManager, get_live_urls
- For each URL: new_page, add_init_script(HOOK_SCRIPT), goto, evaluate(HOOK_SCRIPT)
- For each listener without origin check: _save_vulnerability severity=high
- release_page in finally

**Step 4: Write DomSinkAnalyzer**

DomSinkAnalyzer(WebAppTool):
- name="dom_sink_analyzer", tool_type=BROWSER, weight_class=HEAVY
- SINK_PATTERNS: list of (regex, description) for innerHTML, outerHTML, insertAdjacentHTML,
  DOM write, writeln, setTimeout/setInterval with dynamic args, Function constructor,
  setAttribute with event handler, location assignment
- SOURCE_PATTERNS: list of regex for location.hash/search/href, document.referrer, window.name, URLSearchParams
- _find_sinks(js_content): regex scan, return list of descriptions
- _find_sources(js_content): regex scan, return list of patterns
- execute():
  Phase 1 — Static analysis: read saved JS files, find sinks + sources, if both present -> _save_vulnerability severity=high
  Phase 2 — Playwright trace: goto URL with ?xss_test=probe123, check if probe123 appears in DOM -> _save_vulnerability

**Step 5: Run tests — expected PASS**

**Step 6: Commit**

git commit -m "feat(webapp-worker): add PostMessage and DomSinkAnalyzer tools (Stage 3)"

---

## Task 10: Stage 3 — StorageAuditor + SourcemapDetector + WebSocketAnalyzer

**Files:**
- Create: workers/webapp_worker/tools/storage_auditor.py
- Create: workers/webapp_worker/tools/sourcemap_detector.py
- Create: workers/webapp_worker/tools/websocket_analyzer.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_storage_auditor_flags_sensitive_keys: verify _is_sensitive returns True for "auth_token", "api_key", "sessionId" and False for "theme_preference"
2. test_sourcemap_detector_checks_map_url: verify _get_map_url appends .map
3. test_websocket_analyzer_creates_tool: verify name and tool_type

**Step 2: Run test — expected FAIL**

**Step 3: Write StorageAuditor**

StorageAuditor(WebAppTool):
- name="storage_auditor", tool_type=BROWSER, weight_class=HEAVY
- SENSITIVE_PATTERNS: regex patterns for token, auth, session, secret, api_key, password, jwt, bearer, etc.
- _is_sensitive(key): regex match against patterns
- execute(): get BrowserManager, for each live URL:
  - page.evaluate to read localStorage and sessionStorage key/value pairs
  - For each key matching sensitive pattern: _save_vulnerability severity=medium

**Step 4: Write SourcemapDetector**

SourcemapDetector(WebAppTool):
- name="sourcemap_detector", tool_type=BROWSER, weight_class=LIGHT
- _get_map_url(js_url): append .map
- execute():
  1. Scan saved JS files for sourceMappingURL comments
  2. HTTP probe .map URLs with httpx
  3. If .map returns 200 with "version" in body: _save_vulnerability severity=medium

**Step 5: Write WebSocketAnalyzer**

WebSocketAnalyzer(WebAppTool):
- name="websocket_analyzer", tool_type=BROWSER, weight_class=HEAVY
- execute(): get BrowserManager, for each live URL:
  - Register page.on("websocket") listener
  - page.goto, wait 3 seconds
  - For each WS connection: check URL for auth tokens
  - If no auth found: _save_vulnerability severity=medium
  - _save_observation with WS URL and message count

**Step 6: Run tests — expected PASS**

**Step 7: Commit**

git commit -m "feat(webapp-worker): add StorageAuditor, SourcemapDetector, WebSocketAnalyzer (Stage 3)"

---

## Task 11: Stage 4 — HeaderAuditor + CookieAuditor

**Files:**
- Create: workers/webapp_worker/tools/header_auditor.py
- Create: workers/webapp_worker/tools/cookie_auditor.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_header_auditor_detects_missing_headers:
   - Call _check_headers with mock response missing CSP and HSTS
   - Verify returns list with 2+ missing headers

2. test_cookie_auditor_detects_insecure_cookies:
   - Call _check_cookie with "session=abc; Path=/" (no Secure, no HttpOnly)
   - Verify returns list of issues

**Step 2: Run test — expected FAIL**

**Step 3: Write HeaderAuditor**

HeaderAuditor(WebAppTool):
- name="header_auditor", tool_type=HTTP, weight_class=LIGHT
- REQUIRED_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer leakage protection",
    "Permissions-Policy": "Browser feature restrictions",
  }
- _check_headers(response_headers): returns list of missing header descriptions
- execute(): get_live_urls, httpx GET each URL
  - _save_observation with all response headers
  - For each missing security header: _save_vulnerability severity=medium
  - update_tool_state, return stats

**Step 4: Write CookieAuditor**

CookieAuditor(WebAppTool):
- name="cookie_auditor", tool_type=HTTP, weight_class=LIGHT
- _check_cookie(set_cookie_str): returns list of issues (missing Secure, HttpOnly, SameSite)
- execute(): get_live_urls, httpx GET each URL
  - Parse Set-Cookie headers
  - For each cookie with issues: _save_vulnerability severity=medium
  - update_tool_state, return stats

**Step 5: Run tests — expected PASS**

**Step 6: Commit**

git commit -m "feat(webapp-worker): add HeaderAuditor and CookieAuditor tools (Stage 4)"

---

## Task 12: Stage 4 — CorsTester + FormAnalyzer

**Files:**
- Create: workers/webapp_worker/tools/cors_tester.py
- Create: workers/webapp_worker/tools/form_analyzer.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_cors_tester_detects_reflection:
   - Verify _is_cors_misconfigured returns True when ACAO reflects arbitrary origin

2. test_form_analyzer_detects_missing_csrf:
   - Pass HTML with form lacking CSRF token
   - Verify _analyze_forms returns at least 1 issue

**Step 2: Run test — expected FAIL**

**Step 3: Write CorsTester**

CorsTester(WebAppTool):
- name="cors_tester", tool_type=HTTP, weight_class=LIGHT
- TEST_ORIGINS = ["https://attacker.com", "null"]
- _is_cors_misconfigured(response_headers, test_origin): check if ACAO reflects the test origin or is "*" with credentials
- execute(): get_live_urls, for each URL send httpx GET with Origin header
  - If ACAO reflects: _save_vulnerability severity=high
  - update_tool_state, return stats

**Step 4: Write FormAnalyzer**

FormAnalyzer(WebAppTool):
- name="form_analyzer", tool_type=HTTP, weight_class=LIGHT
- _analyze_forms(html): parse with regex for form tags, check for hidden CSRF inputs and autocomplete on password fields
- execute(): get_live_urls, httpx GET each URL
  - _analyze_forms on response body
  - For each issue: _save_vulnerability severity=medium
  - update_tool_state, return stats

**Step 5: Run tests — expected PASS**

**Step 6: Commit**

git commit -m "feat(webapp-worker): add CorsTester and FormAnalyzer tools (Stage 4)"

---

## Task 13: Stage 5 — SensitivePaths + RobotsSitemap

**Files:**
- Create: workers/webapp_worker/tools/sensitive_paths.py
- Create: workers/webapp_worker/tools/robots_sitemap.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_sensitive_paths_has_wordlist:
   - Verify SENSITIVE_WORDLIST contains at least 10 paths
   - Verify "/.git/HEAD" and "/.env" are in the list

2. test_robots_sitemap_parses_robots:
   - Call _parse_robots with sample robots.txt content
   - Verify extracted paths

**Step 2: Run test — expected FAIL**

**Step 3: Write SensitivePaths**

SensitivePaths(WebAppTool):
- name="sensitive_paths", tool_type=HTTP, weight_class=LIGHT
- SENSITIVE_WORDLIST: list of paths to probe: /.git/HEAD, /.env, /.DS_Store, /wp-config.php,
  /admin, /debug, /actuator/health, /.htpasswd, /server-status, /phpinfo.php,
  /backup.sql, /.svn/entries, /config.yml, /.dockerenv, /api/swagger,
  /elmah.axd, /trace.axd, /web.config
- CRITICAL_PATHS = {".git", ".env", ".htpasswd", "wp-config.php", "web.config"}
- execute(): get_live_urls, for each base URL:
  - httpx HEAD/GET each path in wordlist (concurrently with asyncio.gather)
  - If status 200 or 403 for sensitive paths: _save_vulnerability
  - severity=critical for CRITICAL_PATHS, medium for others
  - _save_asset for any new discovered paths
  - update_tool_state, return stats

**Step 4: Write RobotsSitemap**

RobotsSitemap(WebAppTool):
- name="robots_sitemap", tool_type=HTTP, weight_class=LIGHT
- _parse_robots(text): extract Disallow and Allow paths
- _parse_sitemap(xml_text): extract loc URLs from sitemap XML
- execute(): get_live_urls, for each base URL:
  - httpx GET /robots.txt, parse paths
  - httpx GET /sitemap.xml, parse URLs
  - _save_asset for each discovered path/URL
  - update_tool_state, return stats

**Step 5: Run tests — expected PASS**

**Step 6: Commit**

git commit -m "feat(webapp-worker): add SensitivePaths and RobotsSitemap tools (Stage 5)"

---

## Task 14: Stage 5 — GraphqlProber + OpenApiDetector + OpenRedirect

**Files:**
- Create: workers/webapp_worker/tools/graphql_prober.py
- Create: workers/webapp_worker/tools/openapi_detector.py
- Create: workers/webapp_worker/tools/open_redirect.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing tests**

1. test_graphql_prober_has_common_paths:
   - Verify GRAPHQL_PATHS contains /graphql and /api/graphql

2. test_openapi_detector_has_common_paths:
   - Verify OPENAPI_PATHS contains /swagger.json and /api-docs

3. test_open_redirect_identifies_redirect_params:
   - Verify REDIRECT_PARAMS contains "redirect", "url", "next", "return"

**Step 2: Run test — expected FAIL**

**Step 3: Write GraphqlProber**

GraphqlProber(WebAppTool):
- name="graphql_prober", tool_type=HTTP, weight_class=LIGHT
- GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/gql", "/query"]
- INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'
- execute(): get_live_urls, for each base URL:
  - httpx POST each graphql path with introspection query
  - If response contains "__schema": _save_vulnerability severity=medium (introspection enabled)
  - _save_observation with graphql endpoint info
  - update_tool_state, return stats

**Step 4: Write OpenApiDetector**

OpenApiDetector(WebAppTool):
- name="openapi_detector", tool_type=HTTP, weight_class=LIGHT
- OPENAPI_PATHS = ["/swagger.json", "/api-docs", "/openapi.json", "/v1/api-docs",
  "/v2/api-docs", "/swagger/v1/swagger.json", "/api/swagger.json", "/docs"]
- execute(): get_live_urls, for each base URL:
  - httpx GET each openapi path
  - If response 200 and contains "swagger" or "openapi": _save_asset + _save_observation
  - update_tool_state, return stats

**Step 5: Write OpenRedirect**

OpenRedirect(WebAppTool):
- name="open_redirect", tool_type=HTTP, weight_class=LIGHT
- REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnTo", "goto",
  "redirect_uri", "continue", "dest", "destination", "rurl", "target"]
- execute(): get_live_urls, for each base URL:
  - For each redirect param: httpx GET url?param=https://attacker.com with follow_redirects=False
  - If response 301/302 with Location containing attacker.com: _save_vulnerability severity=medium
  - update_tool_state, return stats

**Step 6: Run tests — expected PASS**

**Step 7: Commit**

git commit -m "feat(webapp-worker): add GraphqlProber, OpenApiDetector, OpenRedirect tools (Stage 5)"

---

## Task 15: Stage 6 — NewmanProber

**Files:**
- Create: workers/webapp_worker/tools/newman_prober.py
- Modify: tests/test_webapp_tools.py

**Step 1: Write the failing test**

test_newman_prober_generates_collection:
- Call _build_collection with sample endpoints
- Verify returned dict has "info" and "item" keys
- Verify each item has request with method and url

**Step 2: Run test — expected FAIL**

**Step 3: Write NewmanProber**

NewmanProber(WebAppTool):
- name="newman_prober", tool_type=CLI, weight_class=LIGHT
- HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
- _build_collection(endpoints, target_name): generates Postman collection JSON dict
  - info: {name, schema: postman collection schema URL}
  - item: for each endpoint, for each method, create request entry
- execute():
  1. Query Asset table for all URLs discovered in earlier stages (asset_type in ("url", "domain"))
  2. If no endpoints: return early
  3. _build_collection(endpoints)
  4. Write collection JSON to tempfile
  5. run_subprocess ["newman", "run", tmpfile, "--reporters", "json", "--reporter-json-export", outfile]
  6. Parse newman JSON output: check for non-2xx responses, auth errors, verbose error messages
  7. For each interesting finding: _save_vulnerability or _save_observation
  8. Clean up temp files
  9. update_tool_state, return stats

**Step 4: Run test — expected PASS**

**Step 5: Commit**

git commit -m "feat(webapp-worker): add NewmanProber tool (Stage 6)"

---

## Task 16: Wire Tools into Pipeline

**Files:**
- Modify: workers/webapp_worker/tools/__init__.py
- Modify: workers/webapp_worker/pipeline.py
- Modify: tests/test_webapp_pipeline.py (un-skip structural tests)

**Step 1: Write tools/__init__.py**

Import all 20 tool classes and define __all__:

```
from workers.webapp_worker.tools.js_crawler import JsCrawler
from workers.webapp_worker.tools.linkfinder import LinkFinder
from workers.webapp_worker.tools.jsminer import JsMiner
from workers.webapp_worker.tools.mantra import Mantra
from workers.webapp_worker.tools.secretfinder import SecretFinder
from workers.webapp_worker.tools.postmessage import PostMessage
from workers.webapp_worker.tools.dom_sink_analyzer import DomSinkAnalyzer
from workers.webapp_worker.tools.storage_auditor import StorageAuditor
from workers.webapp_worker.tools.sourcemap_detector import SourcemapDetector
from workers.webapp_worker.tools.websocket_analyzer import WebSocketAnalyzer
from workers.webapp_worker.tools.header_auditor import HeaderAuditor
from workers.webapp_worker.tools.cookie_auditor import CookieAuditor
from workers.webapp_worker.tools.cors_tester import CorsTester
from workers.webapp_worker.tools.form_analyzer import FormAnalyzer
from workers.webapp_worker.tools.sensitive_paths import SensitivePaths
from workers.webapp_worker.tools.robots_sitemap import RobotsSitemap
from workers.webapp_worker.tools.graphql_prober import GraphqlProber
from workers.webapp_worker.tools.openapi_detector import OpenApiDetector
from workers.webapp_worker.tools.open_redirect import OpenRedirect
from workers.webapp_worker.tools.newman_prober import NewmanProber
```

**Step 2: Update pipeline.py STAGES**

Replace the empty STAGES list with actual tool imports:

```
STAGES = [
    Stage("js_discovery",        [JsCrawler]),
    Stage("static_js_analysis",  [LinkFinder, JsMiner, Mantra, SecretFinder]),
    Stage("browser_security",    [PostMessage, DomSinkAnalyzer, StorageAuditor,
                                  SourcemapDetector, WebSocketAnalyzer]),
    Stage("http_security",       [HeaderAuditor, CookieAuditor, CorsTester, FormAnalyzer]),
    Stage("path_api_discovery",  [SensitivePaths, RobotsSitemap, GraphqlProber,
                                  OpenApiDetector, OpenRedirect]),
    Stage("api_probing",         [NewmanProber]),
]
```

**Step 3: Un-skip structural tests**

Remove @pytest.mark.skip decorators from the 3 structural tests.

**Step 4: Run all tests**

Run: python -m pytest tests/test_webapp_pipeline.py tests/test_webapp_tools.py -v
Expected: All pass

**Step 5: Commit**

git commit -m "feat(webapp-worker): wire all 20 tools into 6-stage pipeline"

---

## Task 17: Dockerfile

**Files:**
- Create: docker/Dockerfile.webapp

**Step 1: Write the Dockerfile**

Three-stage build:

Stage 1 (node-builder): FROM node:20-slim
- npm install -g newman

Stage 2 (py-builder): FROM python:3.10-slim-bookworm
- pip install --target=/py-tools httpx[http2] beautifulsoup4

Stage 3 (runtime): FROM python:3.10-slim-bookworm
- apt-get install: chromium, libglib2.0-0, libnss3, libatk1.0-0, libatk-bridge2.0-0,
  libcups2, libdrm2, libxcomposite1, libxdamage1, libxrandr2, libgbm1, libpango-1.0-0,
  libcairo2, libasound2, libxshmfence1, gcc, libpq-dev, git, nodejs, npm
- pip install playwright && playwright install chromium
- pip install linkfinder secretfinder (or git+https://... if needed)
- COPY from node-builder and py-builder
- COPY shared/lib_webbh and pip install
- COPY workers/__init__.py and workers/webapp_worker
- mkdir /app/shared/raw /app/shared/config /app/shared/logs
- Smoke test: python -c "from workers.webapp_worker.main import main; print('OK')"
- ENTRYPOINT ["python", "-m", "workers.webapp_worker.main"]

Note: Exact package names for mantra/secretfinder/jsminer/linkfinder need verification at build time. Some may be GitHub-only. Add comments in Dockerfile for each.

**Step 2: Commit**

git commit -m "feat(webapp-worker): add multi-stage Dockerfile"

---

## Task 18: Docker Compose Update

**Files:**
- Modify: docker-compose.yml

**Step 1: Add webapp-worker service**

Add after recon-core service block:

```yaml
  webapp-worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.webapp
    container_name: webbh-webapp-worker
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
      MAX_TABS: "3"
      PAGE_TIMEOUT: "30"
    volumes:
      - ./shared:/app/shared
    networks:
      - webbh-net
```

**Step 2: Commit**

git commit -m "feat(webapp-worker): add service to docker-compose.yml"

---

## Task 19: Integration Test

**Files:**
- Create: tests/test_webapp_integration.py

**Step 1: Write integration test**

test_webapp_pipeline_full_flow:
- Set DB_DRIVER=sqlite+aiosqlite, DB_NAME=:memory:
- Create tables
- Seed: Target, Asset (domain), Location (port 80, state=open)
- Mock all subprocess calls (linkfinder, mantra, etc.)
- Mock BrowserManager (page.goto, page.evaluate return empty results)
- Mock httpx responses (return 200 with minimal headers)
- Mock push_task
- Create JobState row with status=RUNNING
- Instantiate Pipeline, call run()
- Verify: JobState.status == COMPLETED
- Verify: push_task called with pipeline_complete event

**Step 2: Run test**

Run: python -m pytest tests/test_webapp_integration.py -v
Expected: PASS

**Step 3: Run all tests**

Run: python -m pytest tests/ -v -k "webapp"
Expected: All pass

**Step 4: Commit**

git commit -m "test(webapp-worker): add integration test with mocked tools"

---

## Summary

| Task | Component | Files |
|------|-----------|-------|
| 1 | Scaffolding | __init__.py, concurrency.py |
| 2 | BrowserManager | browser.py |
| 3 | WebAppTool ABC | base_tool.py |
| 4 | Pipeline | pipeline.py |
| 5 | Entry point | main.py |
| 6 | JsCrawler | tools/js_crawler.py |
| 7 | LinkFinder + JsMiner | tools/linkfinder.py, jsminer.py |
| 8 | Mantra + SecretFinder | tools/mantra.py, secretfinder.py |
| 9 | PostMessage + DomSinkAnalyzer | tools/postmessage.py, dom_sink_analyzer.py |
| 10 | Storage + Sourcemap + WebSocket | tools/storage_auditor.py, sourcemap_detector.py, websocket_analyzer.py |
| 11 | HeaderAuditor + CookieAuditor | tools/header_auditor.py, cookie_auditor.py |
| 12 | CorsTester + FormAnalyzer | tools/cors_tester.py, form_analyzer.py |
| 13 | SensitivePaths + RobotsSitemap | tools/sensitive_paths.py, robots_sitemap.py |
| 14 | GraphQL + OpenAPI + OpenRedirect | tools/graphql_prober.py, openapi_detector.py, open_redirect.py |
| 15 | NewmanProber | tools/newman_prober.py |
| 16 | Wire pipeline | tools/__init__.py, pipeline.py |
| 17 | Dockerfile | docker/Dockerfile.webapp |
| 18 | Docker Compose | docker-compose.yml |
| 19 | Integration test | tests/test_webapp_integration.py |
