# WSTG-INFO-08: Fingerprint Web Application Framework — Stage 8 Design

**Date:** 2026-05-17  
**WSTG Section:** 4.1.8  
**Stage name:** `fingerprint_framework`  
**Worker:** `info_gathering`

---

## Overview

Stage 8 of the `info_gathering` pipeline identifies the web application framework and CMS powering a target. The existing implementation has three tools (`Wappalyzer`, `CookieFingerprinter`, `Webanalyze`) that are broken (wrong `save_observation` call signature) and return `None` implicitly. This design brings Stage 8 to full parity with Stage 2 (`web_server_fingerprint`): `ProbeResult`-returning tools, a `FrameworkFingerprintAggregator`, a post-stage pipeline hook, and `Vulnerability` rows for information disclosure findings.

No changes are required to `playbooks.py`, `worker-stages.ts`, or the dashboard — they already correctly list `fingerprint_framework`.

---

## Architecture

### New files

| File | Purpose |
|------|---------|
| `workers/info_gathering/tools/header_framework_probe.py` | `HeaderFrameworkProbe` — HTTP response header analysis |
| `workers/info_gathering/tools/meta_generator_probe.py` | `MetaGeneratorProbe` — HTML `<meta name="generator">` and secondary HTML signal parsing |
| `workers/info_gathering/tools/framework_file_prober.py` | `FrameworkFileProber` — probes known framework-specific file paths |
| `workers/info_gathering/framework_fingerprint_aggregator.py` | `FrameworkFingerprintAggregator` — scores signals, writes summary Observation, emits Vulnerability rows |

### Modified files

| File | Change |
|------|--------|
| `tools/wappalyzer.py` | Fix `save_observation` call signature; return `ProbeResult` |
| `tools/cookie_fingerprinter.py` | Fix `save_observation` call signature; return `ProbeResult` |
| `tools/webanalyze.py` | Fix `save_observation` call signature; return `ProbeResult` |
| `pipeline.py` | Add `_STAGE8_SECTION = "4.1.8"` constant; add post-stage aggregator hook |
| `concurrency.py` | Add `TOOL_WEIGHTS` entries for `HeaderFrameworkProbe`, `MetaGeneratorProbe`, `FrameworkFileProber` |

### Signal slots

| Slot | Captures |
|------|---------|
| `framework` | Application framework: Django, Laravel, Rails, Spring, Express, ASP.NET MVC |
| `cms` | CMS: WordPress, Joomla, Drupal, Ghost |
| `language` | Runtime language: PHP, Python, Ruby, Java, Node.js, .NET |

Reuses the existing `ProbeResult` dataclass from `fingerprint_aggregator.py` — it is generic and requires no modification.

---

## Tool Designs

### `HeaderFrameworkProbe`

One `aiohttp` GET to `https://{host}`. Reads response headers and maps them to `(slot, vendor, version)` via a signature dict. Saves one Observation with `_probe="header_framework"`. Returns `ProbeResult`.

Header signature map:

| Header | Slot | Vendor | Version extraction |
|--------|------|--------|--------------------|
| `X-AspNetMvc-Version` | `framework` | ASP.NET MVC | Full header value |
| `X-AspNet-Version` | `language` | .NET | Full header value |
| `X-Generator` | `cms` | parsed from value | Regex on value |
| `X-Powered-By: PHP/x.y` | `language` | PHP | Regex on value |
| `X-Powered-By: Express` | `framework` | Express | Static |
| `X-Pingback: /xmlrpc.php` | `cms` | WordPress | None |
| `X-Drupal-Cache` | `cms` | Drupal | None |
| `X-Drupal-Dynamic-Cache` | `cms` | Drupal | None |

Signal weight: `0.7` for version-bearing headers, `0.4–0.5` for presence-only headers.

### `MetaGeneratorProbe`

One `aiohttp` GET, HTML parsed with stdlib `html.parser` (no new dependencies). Checks:

| Signal | Slot | Vendor | Version |
|--------|------|--------|---------|
| `<meta name="generator" content="WordPress x.y.z">` | `cms` | WordPress | From content |
| `<meta name="generator" content="Joomla!...">` | `cms` | Joomla | From content |
| `<meta name="generator" content="Drupal...">` | `cms` | Drupal | From content |
| `<link rel="https://api.w.org/" />` | `cms` | WordPress | None (confirmation) |
| `data-drupal-*` attribute presence | `cms` | Drupal | None |
| `<meta name="csrf-param" content="authenticity_token">` | `framework` | Rails | None |
| Form field `csrfmiddlewaretoken` | `framework` | Django | None |

Saves one Observation with `_probe="meta_generator"`. Returns `ProbeResult`.

Signal weight: `0.8` for `<meta name="generator">` (version-bearing), `0.4–0.5` for secondary confirmation signals.

### `FrameworkFileProber`

Probes a curated path list concurrently via `aiohttp`. HTTP status 200, 301, 302, and 403 all count as "exists" — 403 indicates the server knows the file but restricts access, which is still fingerprint-positive. 404 and network errors are not recorded.

Path list by framework:

| Framework/CMS | Paths |
|---------------|-------|
| WordPress | `/wp-login.php`, `/readme.html`, `/license.txt`, `/wp-includes/js/jquery/jquery.min.js` |
| Joomla | `/administrator/index.php`, `/CHANGELOG.txt`, `/htaccess.txt` |
| Drupal | `/core/CHANGELOG.txt`, `/CHANGELOG.txt` |
| Laravel | `/artisan`, `/.env` |
| Django | `/admin/login/?next=/admin/` |
| Rails | `/rails/info/properties` |

Each path is mapped to `(slot, vendor)`. Matched paths are embedded in the signals dict under `framework_files`. Saves one Observation with `_probe="framework_files"`. Returns `ProbeResult`.

Signal weight: `0.6` per matched path.

### Fixes to existing tools

All three tools have the same two bugs:
1. Pass `target_id` where `asset_id` is expected as the first positional arg to `save_observation`.
2. Pass extra positional strings (`"technology_detection"`, `"tool_name"`) that don't match the keyword-only signature.

Fix: read `asset_id` from `kwargs.get("asset_id")`, pass observation data as `tech_stack={...}`, and return `ProbeResult(probe="<probe_name>", obs_id=obs_id, signals={...})`.

---

## `FrameworkFingerprintAggregator`

Lives in `workers/info_gathering/framework_fingerprint_aggregator.py`. Mirrors `FingerprintAggregator` in structure.

### Signal weights

```python
FRAMEWORK_WEIGHTS = {
    "meta_generator":   0.8,
    "header_framework": 0.7,
    "framework_files":  0.6,
    "wappalyzer":       0.6,
    "webanalyze":       0.6,
    "cookie_framework": 0.5,
}
```

### Methods

**`_score_slot(slot, results)`** — same weight-accumulation logic as `FingerprintAggregator._score_slot`. Sums per-vendor weights across all non-errored probes. Returns `{vendor, confidence, signals, conflict}`.

**`write_summary(results)`** — scores all three slots, writes one `_probe="framework_summary"` Observation against `asset_id`. Returns `obs_id`.

**`emit_disclosures(fingerprint, raw)`** — emits `Vulnerability` rows tagged `section_id="4.1.8"`, `stage_name="fingerprint_framework"`, `worker_type="info_gathering"`. The `raw` dict is assembled by a new `_stage8_raw_from_results` pipeline helper (mirrors `_stage2_raw_from_results`).

### Vulnerability matrix

| Title | Severity | Trigger condition |
|-------|----------|-------------------|
| Framework version disclosed via HTTP header | INFO | `header_framework` probe found a version-bearing header |
| Framework version disclosed via generator meta tag | INFO | `meta_generator` probe found a version-bearing generator tag |
| CMS information file publicly accessible | LOW | `framework_files` probe matched `readme.html`, `CHANGELOG.txt`, or `license.txt` |
| CMS admin interface publicly accessible | LOW | `framework_files` probe matched `/wp-admin/`, `/administrator/`, or `/admin/login/` |
| Corroborated framework version identification | LOW | ≥2 probes agree on the same vendor **and** ≥1 carries a version string |

**Corroboration logic:** after scoring, if any slot has `confidence >= 0.5` and the `raw` dict contains a version string from any probe, gather all contributing `obs_id`s into one consolidated evidence dict and emit a single LOW finding. When a corroborated finding is emitted, individual INFO findings for the same vendor from the same stage are not emitted — the consolidated finding supersedes them.

---

## Pipeline Hook

In `pipeline.py`, add constant and post-stage hook (mirrors the Stage 2 hook at line 246):

```python
_STAGE8_SECTION = "4.1.8"
```

In `run()`, after the existing Stage 7 hook block:

```python
if stage.section_id == _STAGE8_SECTION:
    agg = FrameworkFingerprintAggregator(
        asset_id=asset_id, target_id=self.target_id,
    )
    probe_results = [r for r in results if isinstance(r, ProbeResult)]
    summary_obs_id = await agg.write_summary(probe_results)
    fingerprint = {
        slot: agg._score_slot(slot, probe_results)
        for slot in ("framework", "cms", "language")
    }
    raw = self._stage8_raw_from_results(probe_results)
    vuln_ids = await agg.emit_disclosures(fingerprint, raw)
    stats["probes"] = len(probe_results)
    stats["summary_written"] = summary_obs_id is not None
    stats["vulns"] = len(vuln_ids)
```

`_stage8_raw_from_results` extracts per-probe data from `ProbeResult` signals for the aggregator to consume without re-querying the DB.

---

## Concurrency

All three new tools are `LIGHT` weight — they make a small number of direct HTTP requests and are not subprocess-based.

```python
"HeaderFrameworkProbe": "LIGHT",
"MetaGeneratorProbe":   "LIGHT",
"FrameworkFileProber":  "LIGHT",
```

`FrameworkFileProber` makes ~10–15 concurrent requests internally, gated by its own internal semaphore (limit 5) to avoid hammering the target.

---

## Testing

### Unit tests (`tests/unit/info_gathering/`)

| File | Key assertions |
|------|---------------|
| `test_header_framework_probe.py` | Mock aiohttp responses; verify slot/vendor/version extraction per header signature; `test_wstg_header_version_disclosure` |
| `test_meta_generator_probe.py` | Feed HTML fixture strings; verify generator tag parsing, api.w.org link, csrf-param detection; `test_wstg_meta_generator_cms_detection` |
| `test_framework_file_prober.py` | Mock HTTP responses at each path; verify 200/403 treated as "exists", 404 ignored; `test_wstg_framework_file_prober_path_matching` |
| `test_framework_fingerprint_aggregator.py` | Weight accumulation, conflict detection, corroboration logic (≥2 probes same vendor + version → single LOW, individual INFOs suppressed); `test_wstg_corroborated_version_identification` |

### E2e additions (`tests/e2e/test_info_gathering.py`)

```python
"fingerprint_framework": lambda c, tid: (
    assert_assets(c, tid),
    assert_observations(c, tid, probe="_probe=framework_summary"),
),
```

The `assert_observations` check validates that the aggregator's post-stage hook ran successfully — not just that tools executed.

---

## Out of scope

- JavaScript library detection (jQuery version, React, Angular, Vue) — Wappalyzer already covers this.
- Intensity gating — all probes run at every intensity level.
- Changes to `playbooks.py`, `worker-stages.ts`, or dashboard — already correct.
