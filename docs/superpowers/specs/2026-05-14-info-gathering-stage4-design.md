# Stage 4 Redesign: Enumerate Applications (WSTG-INFO-04)

**Date**: 2026-05-14
**Section**: WSTG-INFO-04 — Enumerate Applications on Webserver
**Status**: Approved

---

## Overview

Stage 4 of the `info_gathering` pipeline currently covers only DNS/subdomain discovery (`enumerate_subdomains`). WSTG-INFO-04 defines three distinct attack-surface vectors:

1. **Non-standard URL paths** — applications served at path prefixes (e.g. `/admin`, `/portal`) distinct from the root application
2. **Non-standard ports** — web services running on ports other than 80/443
3. **DNS / virtual hosts** — subdomains, zone transfers, CT logs, vhost discovery

This redesign expands Stage 4 to cover all three vectors in a single pipeline stage and renames it to `enumerate_applications`.

---

## Pipeline Changes

### Stage 4 — `enumerate_applications` (section `4.1.4`)

**Before**:
```python
Stage(name="enumerate_subdomains", section_id="4.1.4", tools=[
    Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns, VHostProber,
])
```

**After**:
```python
Stage(name="enumerate_applications", section_id="4.1.4", tools=[
    Subfinder, Assetfinder, AmassPassive, AmassActive, Massdns,  # DNS/subdomain vector
    VHostProber,                                                  # virtual host vector
    Naabu,                                                        # non-standard port vector
    AppPathEnumerator,                                            # non-standard URL vector
    CTLogSearcher,                                                # CT log vector
])
```

### Stage 9 — `map_architecture` (section `4.1.9`)

Naabu moves to Stage 4. Stage 9 becomes:
```python
Stage(name="map_architecture", section_id="4.1.9", tools=[Waybackurls, ArchitectureModeler])
```

`ArchitectureModeler` reads Naabu's `port_scan` observations from the DB. Since Stage 4 runs before Stage 9, those rows are already present — no functional change.

---

## New Tools

### `AppPathEnumerator` (`workers/info_gathering/tools/app_path_enumerator.py`)

Wraps `ffuf` to probe the target domain for application-level path prefixes.

**Purpose**: Detect distinct applications hosted at non-root paths (e.g. a separate admin portal at `/admin`, a monitoring app at `/monitor`). Not generic file/directory brute-forcing.

**Command**:
```
ffuf -u https://{host}/FUZZ -w {wordlist_path} -mc 200,201,301,302,307,308,401,403
     -o {tmpfile} -of json -t 20 -timeout 10
```

**Wordlist** (~80 entries, stored inline in the tool):
```
admin, portal, webmail, mail, email, dashboard, api, app, backend,
console, management, wp-admin, phpmyadmin, cpanel, login, secure,
internal, dev, staging, test, demo, backup, monitor, status, health,
swagger, graphql, redoc, docs, api-docs, helpdesk, support, crm,
erp, git, gitlab, jira, confluence, jenkins, sonar, kibana, grafana,
prometheus, vault, registry, nexus, artifactory, wiki, intranet,
vpn, remote, access, connect, extranet, partner, client, customer,
shop, store, cart, checkout, payment, billing, invoice, account,
profile, settings, config, panel, control, manage, report, analytics,
metrics, log, logs, audit, trace, debug, error, exception, system,
service, api-v1, api-v2, v1, v2, v3, rest, rpc, soap, graphiql
```

**Status code filter rationale**:
- `200/201` — direct hit
- `301/302/307/308` — redirect to real content; final destination recorded
- `401/403` — something real exists behind authentication/authorization
- `404` excluded — no application present

**Output**:
- Each discovered path → `Asset(asset_type="url", asset_value=full_url)`
- One `Observation(obs_type="app_path")` per hit: `{status_code, content_length, redirect_url}`
- Scope-checked before saving

**Concurrency**: `LIGHT` weight class. ffuf's `-t 20` caps outbound threads.

---

### `CTLogSearcher` (`workers/info_gathering/tools/ct_log_searcher.py`)

Queries the crt.sh JSON API to enumerate hostnames from Certificate Transparency logs.

**Purpose**: CT logs capture every hostname that has ever appeared in a TLS certificate for the domain — including old staging, dev, and admin subdomains that no longer resolve in DNS. Amass touches CT logs internally but does not surface them as discrete Asset rows.

**Request**:
```
GET https://crt.sh/?q=%.{base_domain}&output=json
```
30-second timeout. Uses `aiohttp` (no subprocess).

**Parsing**:
1. Extract `name_value` from each record
2. Split on newlines (crt.sh packs multiple SANs per entry)
3. Strip wildcard prefixes (`*.`)
4. Deduplicate
5. Scope-check each hostname
6. Save passing hostnames as `Asset(asset_type="subdomain", source="crt.sh")`

DNS resolution is not performed here — `Massdns` (already in Stage 4) resolves all discovered subdomains from the DB at the end of the stage.

**Error handling**: non-200 response or unparseable JSON → log warning, return `{"found": 0}`. Never raises.

---

## Error Handling

All tools run concurrently via `asyncio.gather(..., return_exceptions=True)`. Each tool catches all exceptions internally, logs them, and returns a stats dict. A failure in any single tool does not abort the stage.

- `AppPathEnumerator`: if ffuf is not installed or times out, returns `{"found": 0}`
- `CTLogSearcher`: if crt.sh is unreachable, returns `{"found": 0}`
- `Naabu`: existing behaviour unchanged

---

## Testing

### Unit tests

**`CTLogSearcher`**:
- Mock `aiohttp.ClientSession.get` to return a fixture JSON payload with mixed hostnames (including wildcards and out-of-scope entries)
- Assert: in-scope hostnames saved as Assets; wildcards stripped correctly; out-of-scope entries dropped

**`AppPathEnumerator`**:
- Mock `run_subprocess` to return a ffuf JSON fixture with hits across all filtered status codes and a 404
- Assert: Assets created for filtered codes only; 404 produces no Asset row; Observations record status code and content-length

### E2E / pipeline

The stage rename from `enumerate_subdomains` → `enumerate_applications` is the only breaking change to the e2e suite. Any seeded job fixture or assertion that references `enumerate_subdomains` by name must be updated.

### Stage 9 regression

Confirm `ArchitectureModeler` reads `port_scan` observations correctly after Naabu moves to Stage 4. An integration test that checks for `port_scan` Observation rows after Stage 4 completes is sufficient.

---

## WSTG-INFO-04 Coverage Map

| Guide Vector | Tool(s) |
|---|---|
| Non-standard URL paths | `AppPathEnumerator` (ffuf) |
| Non-standard ports | `Naabu` (moved from Stage 9) |
| Subdomain enumeration | `Subfinder`, `Assetfinder`, `AmassPassive`, `AmassActive`, `Massdns` |
| Virtual hosts | `VHostProber` |
| Certificate Transparency logs | `CTLogSearcher` (crt.sh) |
| DNS zone transfer | Handled internally by `AmassActive` |
