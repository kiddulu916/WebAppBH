# WSTG-CONF-14: HTTP Security Header Misconfigurations — Design Spec

**Date:** 2026-05-21
**Section:** WSTG-CONF-14
**Worker:** `config_mgmt`
**Stage:** `security_headers` (17th stage, after `path_confusion`)

---

## 1. Problem Statement

WSTG-CONF-14 covers HTTP security headers not addressed by earlier CONF sections (HSTS is CONF-07; CSP is CONF-12). A missing or misconfigured header in this group enables concrete attack classes:

- **X-Frame-Options** absent or with deprecated `ALLOW-FROM` → clickjacking
- **X-Content-Type-Options** not set to `nosniff` → MIME-type sniffing attacks
- **Referrer-Policy: unsafe-url** → full URL leakage to cross-origin destinations
- **Permissions-Policy** absent or empty → browser features (camera, geolocation, etc.) unrestricted
- **X-Permitted-Cross-Domain-Policies: all** → Adobe Flash/Reader can read cross-domain data
- **CORS wildcard with credentials** → any origin can make credentialed cross-origin requests (critical)
- **CORS wildcard alone** → any origin can read unauthenticated responses

The guide also calls out generic misconfiguration patterns: empty header values and deprecated directives. These are folded into the per-header classifiers rather than treated as a separate check.

---

## 2. Architecture & Placement

### Pipeline stage

`security_headers` is added as the **17th stage** in `workers/config_mgmt/pipeline.py`, immediately after `path_confusion`:

```python
Stage("security_headers", [HttpSecurityHeadersTester])
```

### Three-layer coherence (updated in the same commit)

| File | Change |
|------|--------|
| `workers/config_mgmt/pipeline.py` | Add `Stage("security_headers", [HttpSecurityHeadersTester])` |
| `shared/lib_webbh/playbooks.py` → `PIPELINE_STAGES["config_mgmt"]` | Append `"security_headers"` |
| `dashboard/src/lib/worker-stages.ts` → `WORKER_STAGES.config_mgmt` | Append `{ id: "16", name: "Security Headers", stageName: "security_headers", sectionId: "WSTG-CONF-14" }` |

### Tool file

`workers/config_mgmt/tools/http_security_headers_tester.py` — pure Python/httpx, no external binary. Overrides `execute()` directly (same pattern as `HstsTester`, `CspTester`, `PathConfusionTester`).

### Registration

- `workers/config_mgmt/tools/__init__.py` — import and `__all__` entry
- `workers/config_mgmt/concurrency.py` → `TOOL_WEIGHTS` — `"http_security_headers_tester": WeightClass.LIGHT`

---

## 3. Tool Internals

### 3.1 Two-phase execution

**Phase 1 — Static security headers** (seeds from `domain`/`subdomain` assets, like `HstsTester`)

For each in-scope host, `GET https://{host}/`. Pass response headers to `_classify_static_headers()`. Checks five header groups: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Permitted-Cross-Domain-Policies.

**Phase 2 — CORS headers** (seeds from `url`/`endpoint`/`page` assets, like `PathConfusionTester`)

For each in-scope URL, `GET {url}` with a synthetic `Origin: https://cors-probe.invalid` request header to trigger CORS response headers. Pass response headers to `_classify_cors()`.

Both phases run within a single `httpx.AsyncClient` (verify=False, follow_redirects=False, timeout=10) bounded by an inner `asyncio.Semaphore(20)`.

### 3.2 Pure helper functions (module-level, unit-testable)

```
_classify_static_headers(host: str, headers: dict) -> list[dict]
_classify_cors(url: str, headers: dict) -> list[dict]
```

Both return lists of `{"vulnerability": {...}}` dicts — no `{"observation": {...}}` dicts.

### 3.3 Severity table

| Header | Condition | Severity |
|--------|-----------|----------|
| X-Frame-Options | Missing | `low` |
| X-Frame-Options | Contains `ALLOW-FROM` (deprecated) | `low` |
| X-Frame-Options | `SAMEORIGIN` or `DENY` | no finding |
| X-Content-Type-Options | Missing | `low` |
| X-Content-Type-Options | Present but not `nosniff` / empty | `medium` |
| X-Content-Type-Options | `nosniff` | no finding |
| Referrer-Policy | Missing | `info` |
| Referrer-Policy | Value is `unsafe-url` | `medium` |
| Referrer-Policy | Any other value | no finding |
| Permissions-Policy | Missing | `info` |
| Permissions-Policy | Present but empty | `low` |
| Permissions-Policy | Non-empty value | no finding |
| X-Permitted-Cross-Domain-Policies | Missing | `info` |
| X-Permitted-Cross-Domain-Policies | `all` or `master-only` | `medium` |
| X-Permitted-Cross-Domain-Policies | `none` | no finding |
| CORS: `Access-Control-Allow-Origin: *` only | Any URL | `medium` |
| CORS: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` | Any URL | `high` |

`info`-severity rows are stored as `{"vulnerability": {"severity": "info", ...}}` — they go to the `vulnerabilities` table, not the asset table. This is consistent with the observation-to-info-vuln refactor described in Section 5.

---

## 4. Error Handling

- **HTTP connect failure / timeout / TLS error**: skip the host or URL silently, log at DEBUG. Absence of a response is not a misconfiguration finding.
- **Non-200 status**: skip that URL for Phase 2 CORS probing (a 404 on an asset URL is not a CORS finding).
- **Empty asset set**: either phase runs to completion with zero findings. No error raised.
- **Out-of-scope assets**: each host and URL is scope-checked before probing. Skipped without logging.

---

## 5. Observation-to-Info-Vulnerability Refactor

### Motivation

`base_tool._process_observation` stores observations as `Asset` rows. This was a practical workaround: the `Observation` model requires an `asset_id` FK, so free-standing security notes were piggybacked onto Asset rows. As a result, informational security findings (e.g. "HSTS preload not configured") end up in the asset table rather than the vulnerabilities table — invisible in the findings view.

Going forward, informational security findings use `{"vulnerability": {"severity": "info", ...}}` and are routed through `_process_vulnerability`, which writes to the `vulnerabilities` table and emits a `NEW_VULNERABILITY` SSE event.

### What stays as Asset observations (downstream-queried)

These four types are functional pipeline records consumed by downstream tools. They must remain as Asset rows:

| `asset_type` | Stored by | Consumed by |
|---|---|---|
| `admin_interface` | `AdminInterfaceFinder` | `DefaultCredentialTester`, `AdminParamTamperer`, `HttpMethodTester` |
| `admin_redirect` | `AdminInterfaceFinder`, `AdminInterfaceEnumerator` | `AdminParamTamperer` |
| `platform_fingerprint` | `PlatformFingerprinter` | `AdminInterfaceEnumerator` |
| `server_software` | `PlatformFingerprinter` | `FileExtensionTester` |
| `api_endpoint` | `ApiDiscoveryTool` | `HttpMethodTester` |
| `cloud_storage` | `CloudStorageAuditor` | `CloudStorageAuditor` (multi-phase self-seeding) |

Converting these to vulnerabilities would silently break downstream pipeline tools.

### What converts to `severity: "info"` vulnerabilities

All security observations that are not downstream-queried. Primary examples:

- `HstsTester`: `hsts_config: no_preload` → `"HSTS preload not configured on {host}"` (severity: info)
- `HstsTester`: `http_redirect: non_redirect` → already handled as vulnerability in some paths; any remaining observation variant converts
- `NetworkConfigTester`: `server_banner` observations (server version disclosed in response headers) → `severity: "low"` vulnerability named "Server software version disclosed: {value}". Note: `server_software` stored by `PlatformFingerprinter` must stay as an Asset (queried by `FileExtensionTester`); `server_banner` in `NetworkConfigTester` is distinct and safe to convert.
- All tools with `test_error` observations (`AdminInterfaceFinder`, `ApiDiscoveryTool`, `FileInclusionTester`, `PlatformFingerprinter`, `RpcTester`) → log only, no DB insert. Test errors are operational failures, not security findings.
- All CONF-14 missing-optional-header cases (Referrer-Policy, Permissions-Policy, X-Permitted-Cross-Domain-Policies)

### What gets dropped (log-only, no DB insert)

Positive confirmatory observations that record "everything is fine":

- `hsts_config: compliant` — HSTS header is present and well-formed
- `http_redirect: to_https` — HTTP correctly redirects to HTTPS

These have no security significance and would pollute the findings table. They are logged at INFO level and not written to any table.

### `base_tool.py` changes

No routing change required in `_process_dict_result`. Each tool simply stops emitting `{"observation": ...}` for security findings and emits `{"vulnerability": {"severity": "info", ...}}` instead. The `_process_observation` path remains for the four Asset-backed types listed above.

---

## 6. Testing

### Unit tests: `tests/unit/config_mgmt/test_http_security_headers_tester.py`

Covers `_classify_static_headers` and `_classify_cors` pure functions only.

`_classify_static_headers` cases:
- Missing X-Frame-Options → `low` finding
- X-Frame-Options `ALLOW-FROM ...` → `low` finding (deprecated directive)
- X-Frame-Options `SAMEORIGIN` → no finding
- Missing X-Content-Type-Options → `low` finding
- X-Content-Type-Options `nosniff` → no finding
- X-Content-Type-Options wrong value → `medium` finding
- X-Content-Type-Options empty string → `medium` finding
- Missing Referrer-Policy → `info` finding
- Referrer-Policy `unsafe-url` → `medium` finding
- Referrer-Policy `no-referrer` → no finding
- Missing Permissions-Policy → `info` finding
- Permissions-Policy empty string → `low` finding
- Permissions-Policy non-empty → no finding
- Missing X-Permitted-Cross-Domain-Policies → `info` finding
- X-Permitted-Cross-Domain-Policies `all` → `medium` finding
- X-Permitted-Cross-Domain-Policies `none` → no finding
- All headers present and correct → empty list

`_classify_cors` cases:
- `ACAO: *` alone → `medium` finding
- `ACAO: *` + `ACAC: true` → `high` finding
- `ACAO: *` + `ACAC: false` → `medium` finding (ACAC false does not downgrade wildcard ACAO)
- `ACAO: https://example.com` → no finding
- No `ACAO` header → no finding

### Unit test updates: existing HSTS tests

`tests/unit/config_mgmt/test_hsts_tester.py` — update any test assertions that currently expect `{"observation": {...}}` format to expect `{"vulnerability": {"severity": "info", ...}}` format. Tests for compliant/to_https cases should assert an empty list (no finding returned).

### E2E test: `tests/e2e/test_config_mgmt.py`

- `LAST_STAGE` → `"security_headers"`
- `STAGE_ASSERTIONS["security_headers"]` → `None`
- `STAGE_TIMEOUTS["security_headers"]` → `180`
- Update module docstring to reference `CONF-01 through CONF-14`
