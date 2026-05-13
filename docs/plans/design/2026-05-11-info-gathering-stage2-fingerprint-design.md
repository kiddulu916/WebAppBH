# Info Gathering Stage 2 — Web Server Fingerprint (WSTG-INFO-02)

**Status:** design
**Date:** 2026-05-11
**Owner:** info_gathering worker
**OWASP reference:** [WSTG-INFO-02 — Fingerprint Web Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)

---

## 1. Goals, scope, and inputs

Stage 2 identifies the web server software, version, OS hints, application framework, WAF/CDN, and TLS profile of **a single host** — the host attached to the current pipeline run. It does not enumerate other hosts, does not do full TCP/UDP discovery, and does not perform CVE matching.

### 1.1 Parent-linkage rule (project-wide invariant Stage 2 must honor)

```
Target (target_id)
  ├── Asset asset_type=domain         (base_domain from target creation)
  ├── Asset asset_type=domain         (other in-scope roots, e.g. acme-cdn.net)
  ├── Asset asset_type=subdomain      (api.acme.com)
  └── Asset asset_type=subdomain      (auth.acme.com)
        ├── Observation rows          (asset_id linkage)
        ├── Location rows             (port/proto under this Asset)
        ├── Directory tree            (under this Asset — separate design)
        └── Vulnerability rows        (target_id + asset_id BOTH set)
```

1. Stage 2 always operates on **one Asset row** (a `domain` or `subdomain`, never a directory or URL path).
2. Every Observation, Location, and Vulnerability Stage 2 writes carries the **subject Asset's `asset_id`** plus the parent Target's `target_id`. No orphan rows on `target_id` alone.
3. If the run's host is the base domain, the subject Asset is the existing `domain`-type Asset created at target creation. Stage 2 does not create a duplicate — it looks up the existing one.
4. If the host is a subdomain or IP, the subject Asset is the `subdomain`/`ip`-type Asset created by Stage 4 (or by ad-hoc ingest). If no Asset row exists, the pipeline preamble upserts one.

### 1.2 Stage 2 inputs (passed via `tool.execute(**kwargs)`)

- `target_id: int`
- `asset_id: int` — resolved by the pipeline preamble before tools run.
- `host: str` — the literal value of `Asset.asset_value`.
- `intensity: Literal["low","medium","high"]` (default `"low"`).
- `scope_manager`, `headers`, `rate_limiter` — unchanged from existing contract.

### 1.3 Stage 2 outputs

1. Up to N raw `Observation` rows — one per probe technique, tagged in `tech_stack._probe`.
2. One **summary `Observation`** with `tech_stack._probe = "summary"`, consolidated fingerprint + confidence.
3. Vulnerability rows of severity `INFO`/`LOW` for clear information disclosure only.
4. Standard `STAGE_COMPLETE` SSE event on `events:{target_id}`.

### 1.4 Out of scope (explicit follow-ups)

- Stage 9 expansion to UDP + full-port TCP — separate design.
- CVE lookup against fingerprinted versions — handled by `reasoning_worker` / `chain_worker`.
- Refactor of URL-as-asset behavior in `Waybackurls` and friends — separate design.

### 1.5 Worked example — `api.acme.com`

```
Target id=42  base_domain="acme.com"
  └─ Asset id=501  target_id=42  asset_type="subdomain"  asset_value="api.acme.com"
        ├─ Location id=L1  asset_id=501  port=443 protocol=tcp service=https
        ├─ Location id=L2  asset_id=501  port=80  protocol=tcp service=http
        ├─ Observation id=1001  asset_id=501  tech_stack._probe="liveness"
        ├─ Observation id=1002  asset_id=501  tech_stack._probe="banner"
        ├─ Observation id=...   (header_order, options, head_vs_get, error_page_404, tls, waf)
        ├─ Observation id=1009  asset_id=501  tech_stack._probe="summary"  ← consolidated answer
        └─ Vulnerability id=V1  target_id=42  asset_id=501  severity="INFO"
                title="Framework version disclosure via X-Powered-By"
```

---

## 2. Tools, probes, and intensity mapping

Stage 2 ships **eight probe units**. Banner/header/error-page work runs in-process via `aiohttp`; only TLS, WAF, and WhatWeb shell out.

| # | Probe unit | Backing impl | Subprocess? | Output `_probe` key |
|---|---|---|---|---|
| 1 | `LivenessProbe`     | `httpx` binary, narrow port list | yes | `liveness` |
| 2 | `BannerProbe`       | aiohttp GET / | no  | `banner` |
| 3 | `HeaderOrderProbe`  | raw-socket GET / (preserves header order/casing) | no | `header_order` |
| 4 | `MethodProbe`       | aiohttp OPTIONS, HEAD, lowercase, garbage verbs | no | `method_options`, `head_vs_get_diff`, `method_quirks` |
| 5 | `ErrorPageProbe`    | aiohttp GET random 16-char path → hash + signature match | no | `error_page_404` |
| 6 | `TLSProbe`          | `tlsx` binary | yes | `tls` |
| 7 | `WAFProbe`          | `wafw00f` (medium/high) + heuristic header/cookie matcher (low) | yes (med/hi) | `waf` |
| 8 | `WhatWebProbe`      | existing `whatweb` binary, refactored for one host + `asset_id` | yes | `app_fingerprint` |

`Nmap` is removed from Stage 2 wiring (moved to Stage 9). `Httpx` is repurposed as the engine inside `LivenessProbe` (single host, ports `80, 443, 8000, 8008, 8080, 8443, 4443, 8888`).

### 2.1 Intensity → probes that run

| Probe | low | medium | high |
|---|:-:|:-:|:-:|
| LivenessProbe        | ✓ | ✓ | ✓ |
| BannerProbe          | ✓ | ✓ | ✓ |
| HeaderOrderProbe     | ✓ | ✓ | ✓ |
| MethodProbe — OPTIONS, HEAD vs GET, lowercase  | ✓ | ✓ | ✓ |
| MethodProbe — HTTP/0.9, PROPFIND, TRACE        |   | ✓ | ✓ |
| MethodProbe — garbage verbs, malformed bodies  |   |   | ✓ |
| ErrorPageProbe — random 404 path               | ✓ | ✓ | ✓ |
| ErrorPageProbe — multi-extension probes        |   | ✓ | ✓ |
| TLSProbe (tlsx, JA3S, ALPN, cert)              | ✓ | ✓ | ✓ |
| WAFProbe — passive header/cookie heuristics    | ✓ | ✓ | ✓ |
| WAFProbe — `wafw00f` active                    |   | ✓ | ✓ |
| WhatWebProbe — default plugins                 | ✓ | ✓ | ✓ |
| WhatWebProbe — aggression `-a 3`               |   |   | ✓ |

### 2.2 Dashboard intensity-selector copy (shown only when the option is focused/selected)

- **Low** — *"Conservative probes that look like normal client variation. Safe against most production targets."*
- **Medium** — *"⚠️ Adds active WAF probing and uncommon HTTP methods (PROPFIND, TRACE, HTTP/0.9). May appear in IDS/WAF logs as suspicious. Use when target authorization clearly covers active reconnaissance."*
- **High** — *"⚠️⚠️ Sends malformed methods, garbage verbs, and aggressive plugin checks. Will trigger WAFs, may be blocked, and is conspicuous to defenders. Only use against authorized targets with explicit go-ahead for noisy fingerprinting."*

### 2.3 Concurrency and rate limiting

All probes run inside `asyncio.gather` within the stage. Each network-touching call passes through `rate_limiter.acquire()` (already wired in `base_tool.py`). Probes register as `WeightClass.LIGHT`.

### 2.4 Required `base_tool.py` fixes (preconditions)

1. Fix `save_observation` signature usage everywhere — current `Httpx` and `WhatWeb` call sites pass `target_id` plus a stray positional string. The signature is `save_observation(asset_id, tech_stack=None, page_title=None, status_code=None, headers=None)`.
2. Add `save_location(asset_id, port, protocol, service, state)` helper.
3. Add `resolve_or_create_asset(target_id, host)` helper used by the pipeline preamble.

---

## 3. Summary aggregation and confidence scoring

A `FingerprintAggregator` runs after the `asyncio.gather` of probes completes. It reads the in-memory `ProbeResult` list (no DB round-trip) and writes one summary Observation.

```python
@dataclass
class ProbeResult:
    probe: str                 # "banner" | "tls" | "waf" | ...
    obs_id: int | None         # raw Observation row this probe wrote
    signals: dict              # vendor candidates with raw evidence
    error: str | None = None   # set if the probe failed; aggregator skips it
```

### 3.1 Signal vocabulary (fixed and small)

| Slot | What it identifies | Probes that feed it |
|---|---|---|
| `edge`          | CDN / reverse proxy in front (Cloudflare, Akamai, Fastly, CloudFront, AzureFD) | banner, tls.cert_issuer, waf, header_order |
| `origin_server` | Actual web server (Apache, nginx, IIS, Caddy, lighttpd, Tomcat) | banner, header_order, method_options, error_page_404 |
| `framework`     | App-layer stack (Express, Django, Rails, ASP.NET, PHP/Laravel) | banner.x_powered_by, app_fingerprint, error_page_404 |
| `os`            | OS hint (only if banner leaks "Ubuntu", "Win32", etc.) | banner, method_quirks |
| `tls`           | JA3S, ALPN, cert issuer/SAN, supported versions | tls |
| `waf`           | WAF/security middleware vendor | waf, header_order |

### 3.2 Scoring rule

```python
WEIGHTS = {
    "banner.server":        0.6,
    "banner.x_powered_by":  0.6,
    "tls.cert_issuer":      0.5,
    "header_order":         0.3,
    "method_options":       0.2,
    "error_page_signature": 0.7,
    "waf_active":           0.9,
    "waf_passive":          0.4,
    "app_fingerprint":      0.5,
}

confidence = min(1.0, sum(weights_for_matched_signals))
```

A vendor is reported only if its summed weight ≥ `0.5`. Below threshold, the slot stays `null` with `signals` listing the weak hits for downstream adjudication.

### 3.3 Conflict handling

If two vendors tie in the same slot (e.g., banner=nginx but error page matches Apache), both are recorded with their independent confidences and `"conflict": true` is set on the slot. The dashboard renders this as an amber warning chip.

### 3.4 Worked summary for `api.acme.com`

```json
{
  "_probe": "summary",
  "intensity": "low",
  "fingerprint": {
    "edge": {
      "vendor": "Cloudflare",
      "confidence": 0.99,
      "signals": [
        {"src": "banner.server",   "value": "cloudflare", "w": 0.6},
        {"src": "tls.cert_issuer", "value": "Cloudflare Inc", "w": 0.5},
        {"src": "waf_passive",     "value": "cf-ray header + __cf_bm cookie", "w": 0.4}
      ]
    },
    "origin_server": {"vendor": null, "confidence": 0.0, "note": "masked by edge", "signals": []},
    "framework":     {"vendor": "Express", "confidence": 0.6, "signals": [{"src": "banner.x_powered_by", "value": "Express", "w": 0.6}]},
    "os":            {"vendor": null, "confidence": 0.0, "signals": []},
    "tls":           {"ja3s": "e7d705…", "alpn": ["h2","http/1.1"], "cert_issuer": "Cloudflare Inc"},
    "waf":           {"vendor": "Cloudflare", "confidence": 0.99}
  },
  "raw_probe_obs_ids": [1001,1002,1003,1004,1005,1006,1007,1008]
}
```

### 3.5 Vulnerability emission rule

The aggregator is the only place that emits Stage 2 Vulnerabilities, keeping logic in one place.

```python
def emit_info_leaks(summary, raw_results) -> list[VulnRow]:
    vulns = []
    if summary["origin_server"]["vendor"] and "version" in summary["origin_server"]:
        vulns.append(VulnRow("Server software and version disclosure", "INFO", evidence=...))
    if "x_powered_by" in raw["banner"]:
        vulns.append(VulnRow("Framework disclosure via X-Powered-By", "INFO", evidence=...))
    if raw["error_page_404"]["signature_match"] in DEFAULT_ERROR_LEAKERS:
        vulns.append(VulnRow("Default error page exposes server internals", "LOW", evidence=...))
    if any(h in INTERNAL_DEBUG_HEADERS for h in raw["banner"]["headers"]):
        vulns.append(VulnRow("Internal debug header exposed to public", "LOW", evidence=...))
    return vulns
```

Each Vuln row is written with `target_id`, `asset_id`, `worker_type="info_gathering"`, `section_id="4.1.2"`, `stage_name="web_server_fingerprint"`, plus an `evidence` dict referencing raw probe Observation IDs.

### 3.6 Failure mode

If N probes errored and M completed, the summary is still written with confidence derived from completed signals and `partial: true`. The stage does not fail on individual probe errors.

---

## 4. File changes, pipeline plumbing, and test plan

### 4.1 File-level change list

**New files**

```
workers/info_gathering/tools/liveness_probe.py
workers/info_gathering/tools/banner_probe.py
workers/info_gathering/tools/header_order_probe.py
workers/info_gathering/tools/method_probe.py
workers/info_gathering/tools/error_page_probe.py
workers/info_gathering/tools/tls_probe.py
workers/info_gathering/tools/waf_probe.py
workers/info_gathering/fingerprint_aggregator.py
workers/info_gathering/fingerprint_signatures.py
tests/test_info_gathering_stage2.py
tests/test_info_gathering_stage2_integration.py
tests/fixtures/stage2/
dashboard/e2e/stage2-fingerprint.spec.ts
```

**Modified files**

| File | Change |
|---|---|
| `workers/info_gathering/pipeline.py` | Add `_resolve_subject_asset(host)` preamble; pass `asset_id`, `host`, `intensity` into `tool.execute(**kwargs)`; replace Stage 2 tool list (drop `Nmap`); after `_run_stage` for Stage 2, call `FingerprintAggregator.write_summary(asset_id, results)`. |
| `workers/info_gathering/base_tool.py` | Fix `save_observation` signature usage; add `save_location(asset_id, port, protocol, service, state)`; add `resolve_or_create_asset(target_id, host)`. |
| `workers/info_gathering/tools/whatweb.py` | Refactor: take `host` + `asset_id` from kwargs, write Observation against `asset_id`, gate `-a 3` on `intensity=="high"`. |
| `workers/info_gathering/tools/httpx.py` | Repurpose as `LivenessProbe`: single host, narrow port list, writes `Location` rows + one Observation with `_probe="liveness"`. |
| `workers/info_gathering/tools/nmap.py` | Removed from Stage 2 wiring. Stays in `tools/` only if Stage 9 imports it. |
| `workers/info_gathering/concurrency.py` | All Stage 2 probes register as `WeightClass.LIGHT`. |
| `shared/lib_webbh/playbooks.py` | Read `fingerprint_intensity` from `playbook.workers.info_gathering.stages[*].config`; default `"low"`. |
| `dashboard/src/components/campaign/PlaybookSelector.tsx` | Add intensity radio with three tooltip strings (Section 2.2). |
| `dashboard/src/components/c2/AssetDetailDrawer.tsx` | Render "Fingerprint" panel when Asset has a `summary` Observation. |
| `docker/Dockerfile.info_gathering` | Install `tlsx` and `wafw00f`. |

### 4.2 Pipeline preamble

```python
# workers/info_gathering/pipeline.py
async def run(self, target, scope_manager, headers=None, playbook=None, rate_limiter=None):
    host = self._select_host(target)
    asset_id = await self._resolve_subject_asset(host)
    intensity = self._get_intensity(playbook)
    
    completed_phase = await self._get_resume_stage()
    start_index = STAGE_INDEX[completed_phase] + 1 if completed_phase else 0
    stages = self._filter_stages(playbook)
    
    for stage in stages[start_index:]:
        await self._update_phase(stage.name)
        results = await self._run_stage(
            stage, target, asset_id, host, intensity,
            scope_manager, headers, rate_limiter,
        )
        if stage.section_id == "4.1.2":
            await FingerprintAggregator(asset_id).write_summary(results)
            await self._emit_info_leak_vulns(asset_id, target.id, results)
        await push_task(f"events:{target.id}", {"event":"STAGE_COMPLETE","stage":stage.name,"stats":results})
        await self._checkpoint_stage(stage.name)
```

`_run_stage` returns each tool's `ProbeResult` (return value, not just `{found,vulnerable}` ints). For non-Stage-2 stages the existing dict shape is preserved — the aggregator only consumes Stage 2 outputs.

### 4.3 Unit tests (`tests/test_info_gathering_stage2.py`)

In-memory aiosqlite + recorded HTTP fixtures.

1. `test_resolve_subject_asset_creates_subdomain_under_target`
2. `test_banner_probe_extracts_server_and_x_powered_by`
3. `test_header_order_probe_records_casing_and_order`
4. `test_method_probe_low_skips_propfind`
5. `test_method_probe_high_includes_garbage_verb_and_records_response`
6. `test_error_page_probe_random_path_and_signature_match`
7. `test_waf_probe_low_passive_only_no_wafw00f_invoked`
8. `test_aggregator_scores_cloudflare_edge_above_threshold`
9. `test_aggregator_records_conflict_when_two_vendors_tie`
10. `test_aggregator_emits_info_leak_vuln_for_x_powered_by`
11. `test_aggregator_handles_partial_results`
12. `test_aggregator_writes_observations_with_correct_asset_id`
13. `test_save_observation_signature_fix_for_whatweb_and_httpx`

### 4.4 Integration tests (`tests/test_info_gathering_stage2_integration.py`)

`aioresponses` for HTTP mocks, real aiosqlite for DB, fakeredis for streams. Each test exercises the full path: pipeline preamble → tools → aggregator → DB writes → SSE event.

| # | Test | What it proves |
|---|---|---|
| I1 | `test_stage2_full_path_cloudflare_target` | 8 probe rows + 1 summary row, correct `asset_id`; summary's `fingerprint.edge.vendor=="Cloudflare"`. |
| I2 | `test_stage2_full_path_bare_nginx_target` | Origin-server slot populated; no edge vendor; banner-derived version reflected. |
| I3 | `test_stage2_writes_locations_for_alive_ports` | `locations` table has one row per alive port under the subject Asset; `uq_locations_asset_port_proto` respected on rerun. |
| I4 | `test_stage2_emits_sse_event_with_stats` | `events:{target_id}` receives `{event:"STAGE_COMPLETE", stage:"web_server_fingerprint", stats:{probes:8, summary_written:true, vulns:N}}`. |
| I5 | `test_stage2_resume_after_crash` | Mid-stage crash leaves checkpoint at the prior stage; rerun re-executes Stage 2 cleanly; summary upserts; raw obs dedup on `(asset_id, _probe)`. |
| I6 | `test_stage2_respects_rate_limiter` | Token-bucket at 2 req/s → wall-clock elapsed ≥ floor(probe_count / 2). |
| I7 | `test_stage2_scope_violation_when_host_out_of_scope` | Records a `ScopeViolation` and exits early; no probe rows written. |
| I8 | `test_stage2_playbook_disables_stage` | `web_server_fingerprint.enabled=false` skips the stage; aggregator not invoked. |
| I9 | `test_stage2_intensity_high_writes_method_quirks_rows` | High-intensity run produces `_probe="method_quirks"` Observation with PROPFIND/TRACE/garbage-verb response details. |
| I10 | `test_stage2_partial_failure_writes_summary_with_partial_flag` | 3/8 probes error; summary has `partial:true` and confidence from completed signals only. |
| I11 | `test_stage2_info_leak_vulnerability_links_evidence` | Vuln's `evidence.probe_obs_id` resolves to a real Observation matching `evidence.value`. |
| I12 | `test_stage2_subject_asset_resolution_idempotent` | Two runs on same host don't create duplicate Asset rows. |
| I13 | `test_stage2_ip_host_uses_ip_asset_type` | Run on `203.0.113.10` resolves an `ip`-typed Asset under same `target_id`. |
| I14 | `test_stage2_default_intensity_when_playbook_omits_field` | Default `"low"` propagates end-to-end. |

### 4.5 Dashboard E2E (`dashboard/e2e/stage2-fingerprint.spec.ts`)

Playwright against a mocked orchestrator (existing fixture pattern).

| # | Test | What it proves |
|---|---|---|
| E1 | `intensity selector renders three options with sequential warnings` | Focus Low → brief description; Medium → light warning; High → major warning. |
| E2 | `selected intensity persists into playbook payload` | Picking "Medium" + Save → POST body contains `…fingerprint_intensity == "medium"`. |
| E3 | `fingerprint panel renders for asset with summary observation` | After SSE `STAGE_COMPLETE` for 4.1.2, drawer shows Edge / Origin / Framework / WAF chips. |
| E4 | `raw signals expandable lists every probe row` | "View signals" expands one row per `_probe` key. |
| E5 | `conflict slot renders amber warning chip` | banner=nginx + error_page=Apache → `Origin: nginx ⚠ conflict` with both candidates. |
| E6 | `info-leak vulnerabilities appear in vuln list with section_id 4.1.2` | Vuln list filtered by `4.1.2` shows the X-Powered-By entry. |
| E7 | `partial summary shows partial badge` | `partial:true` fixture → "Partial" badge next to confidence. |
| E8 | `intensity warning text matches the canonical strings from Section 2.2` | Snapshot test guards the three exact strings. |

Both suites are required to ship before Stage 2 is enabled by default in any playbook.

### 4.6 Manual verification checklist (for implementation plan)

- Run against a known Cloudflare-fronted target → edge=Cloudflare ≥0.95, origin masked.
- Run against a vanilla nginx box → origin=nginx with version if banner present.
- Run against an IIS box at `intensity=high` → method_quirks records IIS-specific PROPFIND responses.
- Confirm `tlsx` and `wafw00f` are present in the worker container.
