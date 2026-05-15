# WSTG-INFO-05 Stage 5 Redesign

**Date:** 2026-05-15
**WSTG section:** WSTG-INFO-05 — Review Web Page Content for Information Leakage
**Worker:** `workers/info_gathering`

## Context

Stage 5 (`review_comments`, section_id `4.1.5`) currently has two tools:

- `CommentHarvester` — fetches the root page, extracts inline HTML/JS comments via regex
- `MetadataExtractor` — downloads discovered document assets (PDF, DOCX, etc.), runs `exiftool` on them

WSTG-INFO-05 covers five distinct leakage categories, three of which are unaddressed:

| WSTG-INFO-05 category | Current coverage |
|---|---|
| HTML comments | CommentHarvester (partial — root page only) |
| META tags | CommentHarvester (partial) |
| JavaScript file secrets (API keys, credentials, IPs) | **Not covered** |
| Source map file exposure | **Not covered** |
| Redirect response body leakage | **Not covered** |
| Generated file metadata | MetadataExtractor |

Additionally, `MetadataExtractor` uses blocking `subprocess.run` for its `exiftool` call, which blocks the asyncio event loop in violation of the worker pattern.

## Approach

DB-first: each new tool queries the DB for URL assets discovered by prior stages (Stages 1–4 on first run; Stages 1–7 on second run), and falls back to parsing the root page when the DB is sparse. Tools are idempotent — they skip URLs for which an observation from the same source already exists in the DB.

## New Tool Files

### `js_secret_scanner.py` — `JsSecretScanner`

**Purpose:** Identify hardcoded secrets in external JavaScript files.

**Behaviour:**
1. Query DB for URL assets where `asset_value` ends in `.js`. If none found, fetch the root page HTML and extract `<script src="...">` links.
2. Download each JS file into a shared temporary directory.
3. Run `trufflehog filesystem <tmpdir> --json` via `asyncio.create_subprocess_exec`.
4. Run `gitleaks detect --source <tmpdir> --report-format json --report-path <out>` via `asyncio.create_subprocess_exec`.
5. Parse both JSON outputs, deduplicate findings by secret value.
6. Persist each unique finding as a `Vulnerability` record (severity `medium`) and a linked `Observation`.
7. Clean up the temp directory on completion or error.

**Concurrency weight:** `HEAVY` — spawns two external processes per JS batch.

---

### `source_map_prober.py` — `SourceMapProber`

**Purpose:** Detect exposed source map files that leak original (unminified) frontend source code.

**Behaviour:**
1. Query DB for URL assets ending in `.js` or `.css`. Fallback: parse root page `<script src>` and `<link href>` attributes.
2. Skip URLs for which an observation with `source="source_map_prober"` already exists in the DB.
3. For each candidate, issue an async HEAD request to `<url>.map`. On non-HEAD support, fall back to GET with streaming disabled.
4. On HTTP 200, save an `Observation` with `obs_type="source_map_exposure"` and the `.map` URL.

**Concurrency weight:** `LIGHT`.

---

### `redirect_body_inspector.py` — `RedirectBodyInspector`

**Purpose:** Capture leaked content in 3xx redirect response bodies, which browsers silently discard.

**Behaviour:**
1. Query DB for all URL assets. Fallback: parse root page links.
2. Skip URLs for which an observation with `source="redirect_body_inspector"` already exists in the DB.
3. Fetch each URL with `allow_redirects=False` and a short timeout.
4. On 3xx response, read the response body.
5. Pattern-match body against sensitive-content indicators: auth tokens, stack traces, internal IP patterns (`10.x`, `172.16–31.x`, `192.168.x`), credential keywords (`password`, `secret`, `api_key`).
6. On any match, save an `Observation` with `obs_type="redirect_body_leakage"` and the matched patterns.

**Concurrency weight:** `LIGHT`.

---

## Fix: `MetadataExtractor` — Blocking Subprocess

`MetadataExtractor._extract_metadata` currently calls `subprocess.run(["exiftool", ...])`, which is synchronous and blocks the event loop. Replace with `asyncio.create_subprocess_exec` and `await proc.communicate()` to match the worker pattern used across all other tools.

## Stage 5 — Updated Tool List

```python
Stage(name="review_comments", section_id="4.1.5", tools=[
    CommentHarvester,
    MetadataExtractor,
    JsSecretScanner,
    SourceMapProber,
    RedirectBodyInspector,
])
```

All five tools run concurrently. At Stage 5 time, the DB contains assets from Stages 1–4 (search engine recon, fingerprinting, metafiles, subdomain/path enumeration).

## Stage 7 — Split into Two Entries

The current `map_execution_paths` stage is kept as-is. A new stage `review_comments_deep` is inserted immediately after:

```python
Stage(name="map_execution_paths", section_id="4.1.7", tools=[Katana, Hakrawler]),
Stage(name="review_comments_deep", section_id="4.1.5", tools=[
    CommentHarvester,
    MetadataExtractor,
    JsSecretScanner,
    SourceMapProber,
    RedirectBodyInspector,
]),
```

By the time `review_comments_deep` executes, Katana and Hakrawler have written all newly discovered URLs (including deep-linked JS files and downloadable documents) to the DB. Because each tool skips URLs with existing observations, only net-new assets discovered during Stage 7 are processed.

The pipeline grows from 10 to 11 stages. `STAGE_INDEX` is rebuilt automatically from the `STAGES` list so no manual index updates are needed.

## Concurrency Configuration

| Tool | Weight |
|---|---|
| `JsSecretScanner` | `HEAVY` |
| `SourceMapProber` | `LIGHT` |
| `RedirectBodyInspector` | `LIGHT` |
| `CommentHarvester` | `LIGHT` (unchanged) |
| `MetadataExtractor` | `LIGHT` (unchanged — per `concurrency.py` line 33) |

The three new tools must be added to the `TOOL_WEIGHTS` dict in `workers/info_gathering/concurrency.py`:

```python
"JsSecretScanner": "HEAVY",
"SourceMapProber": "LIGHT",
"RedirectBodyInspector": "LIGHT",
```

## Docker / Requirements

`trufflehog` and `gitleaks` are binary tools (not Python packages) and must be installed in the `info_gathering` container image. Add installation steps to `docker/Dockerfile.info_gathering`.

## Out of Scope

- Changes to other workers or pipeline stages beyond those listed above
- Dashboard UI changes
- Modifying the `DeepClassifier` post-stage classification logic
