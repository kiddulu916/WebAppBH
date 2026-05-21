# WSTG-CONF-13: Path Confusion Testing — Design Spec

**Date:** 2026-05-21  
**Section:** WSTG-CONF-13  
**Worker:** `config_mgmt`  
**Stage:** `path_confusion` (16th stage, after `csp_testing`)

---

## 1. Problem Statement

Path confusion occurs when a web server's routing layer matches requests intended for dynamic endpoints against static-asset-looking URLs (e.g. `/dashboard/x.js`). When combined with a CDN or reverse proxy that caches by file extension, an attacker can trick the cache into storing a copy of sensitive authenticated content under a publicly-accessible static URL — known as **Web Cache Deception**.

OWASP WSTG-CONF-13 defines the test methodology: append fake static extensions to known dynamic endpoints and observe whether the server returns the original sensitive content on the confused path.

---

## 2. Architecture & Placement

### Pipeline stage
`path_confusion` is added as the **16th stage** in `workers/config_mgmt/pipeline.py`, immediately after `csp_testing`:

```python
Stage("path_confusion", [PathConfusionTester])
```

### Three-layer coherence (updated in the same commit)

| File | Change |
|------|--------|
| `workers/config_mgmt/pipeline.py` | Add `Stage("path_confusion", [PathConfusionTester])` |
| `shared/lib_webbh/playbooks.py` → `PIPELINE_STAGES["config_mgmt"]` | Append `"path_confusion"` |
| `dashboard/src/lib/worker-stages.ts` → `WORKER_STAGES.config_mgmt` | Append `{ id: "15", name: "Path Confusion", stageName: "path_confusion", sectionId: "WSTG-CONF-13" }` |

### Tool file
`workers/config_mgmt/tools/path_confusion_tester.py` — pure Python/httpx, no external binary dependency. Follows the same pattern as `FileExtensionTester` and `CspTester` (overrides `execute()` directly).

### Registration
- `workers/config_mgmt/tools/__init__.py` — import and `__all__` entry
- `workers/config_mgmt/concurrency.py` → `TOOL_WEIGHTS` — `"path_confusion_tester": WeightClass.LIGHT`

---

## 3. Tool Internals

### 3.1 Seed collection

Query the database for all assets with `asset_type IN ('url', 'page', 'endpoint')` scoped to `target_id`. Deduplicate by full URL value. This is the same query used by `FileExtensionTester._fetch_path_stems`, but returning full URLs rather than path stems.

### 3.2 Baseline probe

For each seed URL, issue a GET request and record:
- `status_code`
- `body_text` (decoded, up to a reasonable cap e.g. 50 KB for comparison)
- `content_length`

Seeds returning non-200 status are skipped — they cannot demonstrate path confusion if the canonical path is already broken.

### 3.3 Confused-path probes

For each 200-baseline URL, append 6 static-asset suffix variants (chosen because CDNs most commonly cache these extensions by default):

| Suffix | Rationale |
|--------|-----------|
| `/x.js` | JavaScript — universally cached |
| `/x.css` | Stylesheet — universally cached |
| `/x.png` | Image — universally cached |
| `/x.ico` | Favicon — cached by most CDNs |
| `/x.json` | API responses — cached by some CDNs |
| `/x.woff` | Web font — cached with long TTLs |

URL construction: `{seed_url.rstrip("/")}/x.{ext}` — a single path segment is appended, not a query parameter, matching the canonical attack pattern.

### 3.4 Similarity check

```python
from difflib import SequenceMatcher

ratio = SequenceMatcher(None, baseline_body, confused_body).ratio()
is_confused = ratio > 0.85
```

The 0.85 threshold is conservative enough to survive minor dynamic content differences (CSRF tokens, timestamps) while filtering out generic error pages.

### 3.5 Severity classification

If `is_confused` is True, inspect the **confused response's** `Cache-Control` header:

| Cache-Control contains | Severity | Reasoning |
|------------------------|----------|-----------|
| `no-store`, `private`, or `no-cache` absent | `high` | CDN will cache authenticated content; directly exploitable |
| Any of `no-store`/`private`/`no-cache` present | `medium` | Server-side routing misconfiguration confirmed; CDN exploitation depends on CDN config |

One `Vulnerability` row is inserted per unique `(seed_url, confused_suffix)` pair. The vulnerability `title` is keyed on the confused URL so duplicate runs do not re-insert.

### 3.6 Concurrency

- **Outer semaphore:** `WeightClass.LIGHT` (from `concurrency.py`)
- **Inner HTTP semaphore:** `asyncio.Semaphore(20)` — matches `FileExtensionTester`
- All probes for a given baseline URL run concurrently via `asyncio.gather`

---

## 4. Error Handling

| Condition | Behaviour |
|-----------|-----------|
| `httpx.RequestError` on any probe | Skip that URL silently — network errors expected on broad scans |
| Baseline returns non-200 | Skip seed — no meaningful confusion possible |
| No `url`/`page`/`endpoint` assets in DB | Return `{"found": 0, "in_scope": 0, "new": 0}` cleanly |
| `asyncio.TimeoutError` (whole tool) | Caught by outer `execute()` wrapper; emits `TOOL_PROGRESS` at 100% with timeout message |
| Binary not found | N/A — tool is pure Python, no subprocess |

---

## 5. Output / DB Schema

Findings are stored as `Vulnerability` rows via the existing `_process_vulnerability()` path in `ConfigMgmtTool`:

```python
{
    "vulnerability": {
        "name": f"Path Confusion: {confused_url}",
        "severity": "high" | "medium",
        "description": f"{confused_url} returned content matching {seed_url} (similarity {ratio:.0%}). Cache-Control: {cache_control_value}. A CDN may cache this response under the static-looking URL, exposing it to unauthenticated users.",
        "location": confused_url,
        "section_id": "WSTG-CONF-13",
    }
}
```

Observations (e.g. a confused URL that returned 200 but with headers blocking caching) are stored as `Asset` rows with `asset_type="path_confusion_obs"` for informational tracking without raising a vulnerability.

---

## 6. Testing

### E2E test updates (`tests/e2e/test_config_mgmt.py`)

- `LAST_STAGE` → `"path_confusion"`
- `STAGE_ASSERTIONS["path_confusion"]` → `None` (no guaranteed findings on the test target)
- `STAGE_TIMEOUTS["path_confusion"]` → `180`
- Module docstring updated to `WSTG-CONF-01 through CONF-13`

### Unit tests

Two pure functions are unit-testable in isolation (no I/O):

1. `_is_cacheable(headers: dict) -> bool` — returns True if Cache-Control lacks `no-store`/`private`/`no-cache`
2. `_analyze_confused_response(baseline_body, confused_body, confused_headers) -> dict | None` — returns a vulnerability dict or None

These can live in `tests/unit/test_path_confusion_tester.py` if the `tests/unit/` directory exists, otherwise inline in the e2e conftest.

---

## 7. Files Changed

| File | Change type |
|------|-------------|
| `workers/config_mgmt/tools/path_confusion_tester.py` | **New** |
| `workers/config_mgmt/tools/__init__.py` | Add import + `__all__` entry |
| `workers/config_mgmt/pipeline.py` | Add 16th stage |
| `workers/config_mgmt/concurrency.py` | Add `TOOL_WEIGHTS` entry |
| `shared/lib_webbh/playbooks.py` | Append stage to `config_mgmt` list |
| `dashboard/src/lib/worker-stages.ts` | Append stage to `config_mgmt` array |
| `tests/e2e/test_config_mgmt.py` | Update `LAST_STAGE`, `STAGE_ASSERTIONS`, `STAGE_TIMEOUTS` |
