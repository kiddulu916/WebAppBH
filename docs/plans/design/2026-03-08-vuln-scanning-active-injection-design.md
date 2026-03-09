# Vulnerability Scanning & Active Injection Testing — Design Document

**Date:** 2026-03-08
**Scope:** Phase 5, 6, 7, 8, 11 — Cross-phase injection testing distribution

## Overview

This design distributes active vulnerability testing across five phases based on attack surface alignment. The core principle: each tool lives in the phase whose data and context it naturally consumes.

- **Phase 5 (Web App):** Client-side attacks — XSS, prototype pollution
- **Phase 6 (Fuzzing):** Parameter/header fuzzing variants — CRLF, open redirect
- **Phase 7 (Vuln Scanner):** Server-side injection + transport attacks — SQLi, SSTI, XXE, CMDi, SSRF, request smuggling, host header, deserialization
- **Phase 8 (API Testing):** API-specific attacks — JWT, OAuth, CORS, NoSQL injection, IDOR, mass assignment, rate-limiting, GraphQL abuse
- **Phase 11 (Network):** Service-level attacks — LDAP injection

## Phase 7 — Vuln Scanner (Primary Design)

### Architecture

3-stage sequential pipeline with triage routing. Follows the same `Stage`/`Pipeline` pattern established in Phase 6's fuzzing worker.

### Stage 1: `nuclei_sweep`

Full Nuclei template scan across all live assets.

**Tooling:**
- Nuclei (ProjectDiscovery) with daily-synced Nuclei-Templates + Cent community templates
- Custom templates in `/app/shared/custom_templates/`

**Inputs:**
- `locations` table — port 80/443, state='open'
- `assets` table — asset_type='url' (discovered by Phase 6)
- `cloud_assets` table — bucket URLs for misconfiguration checks

**Context-aware filtering:**
- Query `observations.tech_stack` for technology fingerprints
- Apache detected → Apache-specific templates
- WordPress detected → WP plugin/core templates
- Java/Spring → Java-specific CVE templates
- Filter out templates matching `oos_attacks` list (No DoS, No Brute Force)

**Output:**
- Every finding → `vulnerabilities` table with severity, template-ID in `source_tool` ("nuclei:<template-id>"), description, and PoC (matched request/response pair)
- Severity >= High → immediate `alerts` table insertion
- Each vuln linked to specific `asset_id`

### Stage 2: `active_injection` (Nuclei-Triaged)

Query Stage 1 findings from `vulnerabilities` where `source_tool LIKE 'nuclei:%'` and route to the appropriate active tool for deep confirmation.

**Routing logic:**

| Nuclei Finding Type | Active Tool | Configuration |
|---------------------|-------------|---------------|
| SQLi (template tags: sqli, sql-injection) | **sqlmap** | `--risk` and `--level` based on Nuclei severity. `--tamper` for WAF bypass. `--batch` for non-interactive |
| SSTI (template tags: ssti, template-injection) | **tplmap** | Engine auto-detected from `observations.tech_stack` (Jinja2, Twig, Freemarker, Mako, Pebble, Velocity, Smarty) |
| XXE (template tags: xxe, xml) | **XXEinjector** | OOB exfiltration via interactsh callback URL. Tests: file read, SSRF, DoS (if not in oos_attacks) |
| Command Injection (template tags: rce, cmdi) | **commix** | `--technique` auto-selected (classic, time-based, file-based). `--delay` from rate_limit |
| SSRF (template tags: ssrf) | **SSRFmap** | Internal IP ranges (10.x, 172.16.x, 192.168.x) + cloud metadata (169.254.169.254, metadata.google.internal) |

**Behavior:**
- Confirmed vulns update the existing `vulnerabilities` record: severity escalated, PoC replaced with full exploit proof, `source_tool` updated to "sqlmap", "tplmap", etc.
- Unconfirmed findings remain with original Nuclei severity

### Stage 3: `broad_injection_sweep`

Run active tools against the full injectable surface regardless of Nuclei findings. Catches vulnerabilities that Nuclei templates miss.

**Inputs:**
- All `assets` (type='url') joined with `parameters` table
- All `locations` (port 80/443, state='open')
- Skip any target+parameter combos already confirmed in Stage 2

**Tools run in parallel:**

| Tool | Target Set | Notes |
|------|-----------|-------|
| **sqlmap** | All URLs with parameters (from `parameters` table) | `--forms` for form discovery, `--crawl=1` |
| **tplmap** | URLs with parameters where `tech_stack` suggests template engine | Skip if no template engine detected |
| **commix** | All URLs with parameters | All techniques enabled |
| **SSRFmap** | URLs where `param_name` matches: url, redirect, proxy, callback, next, return, dest, uri, path, forward, target, rurl, src, href | Focused on redirect-capable params |
| **smuggler** | All live HTTP locations | Raw socket — CL.TE, TE.CL, TE.TE detection. No parameter dependency |
| **host_header_tool** (custom Python) | All live locations + Phase 6 vhosts | Tests: password reset poisoning (inject Host in reset flow), cache poisoning (X-Forwarded-Host), routing-based SSRF (Host to internal) |
| **ysoserial** | URLs where `tech_stack` shows Java/Spring/Tomcat | Gadget chains: CommonsCollections, Spring, Hibernate. Only when serialization indicators present |
| **phpggc** | URLs where `tech_stack` shows PHP/Laravel/Symfony | Gadget chains per detected framework version |

### Deduplication

Before running any active tool against a target+parameter combination, check `vulnerabilities` table for existing confirmed finding with a non-Nuclei `source_tool`. Skip if already confirmed with PoC.

### Rate Limiting

All tools inherit `rate_limit` from `target_profile`:
- sqlmap: `--delay` flag
- commix: `--delay` flag
- tplmap: `--delay` flag
- smuggler: inherently slow (1 request per test)
- host_header_tool: configurable delay per request

### Persistence (24-Hour Rule)

Use `job_state` table to track last scan time per asset+tool combination. Skip if scanned within 24 hours unless `force_scan` flag is set in the task message.

### Dockerfile

- **Base:** Debian-slim with Go 1.21+ and Python 3.10+
- **Go tools:** Nuclei (go install)
- **Python tools:** sqlmap, tplmap, commix (pip/git clone)
- **Binary tools:** XXEinjector (Ruby), smuggler (Python), SSRFmap (Python)
- **Java tools:** ysoserial (pre-built JAR, requires JRE)
- **PHP tools:** phpggc (git clone, requires PHP CLI)
- **Template sync:** Cron job or entrypoint script for daily Nuclei-Templates + Cent update

---

## Phase 5 — Web App Worker (Additions)

Two new stages added after existing DOM/JS analysis:

### Stage 5: `xss_scanning`

**Tool:** dalfox

**Input:** `assets` (type='url') with parameters + DOM sinks identified by existing Playwright sink analysis.

**Output:** Reflected/stored XSS findings → `vulnerabilities` with full PoC (payload + reflected response). Complements existing DOM XSS sink detection which only tests basic payloads.

**Why Phase 5:** dalfox benefits from the headless browser context Playwright provides. DOM XSS detection is already here — adding reflected/stored scanning keeps all XSS testing in one place.

### Stage 6: `prototype_pollution`

**Tool:** ppmap

**Input:** JS file URLs discovered by LinkFinder/JSMiner, plus all `assets` (type='url') where `observations.tech_stack` contains Node.js/Express.

**Output:** Client-side and server-side prototype pollution → `vulnerabilities`. Triggered only when JS frameworks detected.

**Why Phase 5:** Phase 5 already has the JS file inventory and headless browser running. Prototype pollution is a JS-layer attack.

---

## Phase 6 — Fuzzing Worker (Additions)

One new stage added after existing Stage 4 (header_fuzzing):

### Stage 5: `injection_fuzzing`

Two tools run concurrently:

**Tool 1:** crlfuzz

**Input:** `assets` (type='url') + `parameters` table.

**Output:** CRLF injection via `%0d%0a` in params and headers → `vulnerabilities` with response-splitting PoC. Natural extension of HeaderFuzzTool.

**Tool 2:** Oralyzer

**Input:** `parameters` where `param_name` matches: redirect, url, next, return, goto, dest, continue, redir, forward, target, rurl, out, view, link.

**Output:** Open redirect findings → `vulnerabilities`. Flags OAuth-redirect chains as high severity.

**Why Phase 6:** Both are fuzzing-class operations — spraying payloads into known parameters/headers. They reuse Phase 6's existing rate-limiting and scope validation infrastructure.

---

## Phase 8 — API Testing (Expansion)

### Revised 4-Stage Pipeline

#### Stage 1: `api_discovery` (enhanced from original)

Existing tools unchanged:
- Kiterunner for API endpoint brute-forcing
- Swagger/OpenAPI spec parsing
- GraphQL introspection via GraphQLmap/InQL
- TruffleHog on API docs

Writes API map to `api_schemas` table.

#### Stage 2: `auth_testing` (new)

Three tools run concurrently:

**jwt_tool:**
- Input: `observations.headers` where `Authorization: Bearer` contains JWT pattern (3 base64 dot-separated segments)
- Tests: algorithm confusion (none, HS256↔RS256), key brute-force (rockyou), claim tampering (sub, role, exp), JWK injection, kid path traversal
- Output: JWT bypass findings → `vulnerabilities` with manipulated token as PoC

**OAuth testing (custom Python tool):**
- Input: `assets` (type='url') where path matches `/oauth/`, `/authorize`, `/callback`, `/auth/`, `/login`, or `observations.headers` contains OAuth-related response headers
- Tests: authorization code flow manipulation, state parameter CSRF, redirect_uri validation bypass, token leakage in referrer, scope escalation, PKCE downgrade
- Output: OAuth flow vulns → `vulnerabilities`

**CORScanner:**
- Input: all `assets` (type='url') containing `/api/` paths
- Tests: Origin reflection, null origin trust, subdomain wildcard, credential leakage via `Access-Control-Allow-Credentials: true`
- Output: CORS misconfig findings → `vulnerabilities`

#### Stage 3: `injection_testing` (enhanced from original)

Three tools run concurrently:

**BOLA/IDOR (enhanced):**
- Original: basic numeric ID iteration
- Enhanced: UUID/slug enumeration, horizontal + vertical privilege escalation, compare responses across two auth contexts (user A's token → user B's resources)
- Input: API endpoints from `api_schemas` with path parameters (`:id`, `:userId`, etc.)

**Mass Assignment (enhanced):**
- Original: basic `{"is_admin": true}` injection
- Enhanced: systematic field discovery — parse API responses for all returned fields, replay each as writable. Test PATCH/PUT/POST. Flag role/permission/balance/verified/email_confirmed fields
- Input: API write endpoints from `api_schemas`

**nosqlmap:**
- Input: `assets` (type='url') containing `/api/` where `observations.tech_stack` shows MongoDB/CouchDB/Express/Node.js
- Tests: MongoDB operator injection (`$gt`, `$ne`, `$regex`), authentication bypass, data extraction
- Output: NoSQL injection findings → `vulnerabilities`

#### Stage 4: `abuse_testing` (new)

Two tools run concurrently:

**Rate-Limit testing (custom Python tool):**
- Input: `assets` (type='url') matching login/reset/otp/register/transfer/payment paths
- Tests: burst N identical requests to sensitive endpoints, measure response code/timing drift, detect missing `429`/`Retry-After` headers
- Burst count configurable from `target_profile` to stay within scope
- Output: rate-limit bypass findings → `vulnerabilities` (severity: medium)

**GraphQL abuse (graphql-cop + enhanced):**
- Input: GraphQL endpoints discovered in Stage 1
- Tests: batching DoS potential, field suggestion info leakage, introspection enabled in production, query depth/complexity limit testing, mutation abuse
- Output: GraphQL misconfig findings → `vulnerabilities`

---

## Phase 11 — Network Testing (Addition)

One new stage added after Nmap/Medusa credential testing:

### New Stage: `ldap_injection`

**Tool:** Custom Python payloads

**Input:**
- `assets` (type='url') where `observations.tech_stack` shows LDAP/Active Directory/OpenLDAP
- `locations` where `service` matches LDAP (port 389/636)
- Login forms on web assets when backend LDAP is suspected from headers/error messages

**Tests:**
- LDAP filter manipulation: `*)(uid=*`, `)(cn=*`
- Blind LDAP via response timing
- Authentication bypass via `*)(&`
- Wildcard data extraction

**Output:** LDAP injection findings → `vulnerabilities` with full payload + response as PoC.

**Why Phase 11:** LDAP injection targets the LDAP protocol/service directly, or web forms backed by LDAP. Phase 11 already enumerates these services and has the context to know LDAP is present.

---

## Database Usage Summary

All phases write to the same tables using existing `lib_webbh` models:

| Table | Write Pattern |
|-------|--------------|
| `vulnerabilities` | Every confirmed finding. `severity` (Critical/High/Medium/Low/Info), `title`, `description`, `poc` (full request/response), `source_tool` (tool name), linked to `target_id` + `asset_id` |
| `alerts` | Auto-created for every finding with severity >= High |
| `job_state` | Updated per stage for checkpointing and 24-hour cooldown tracking |
| `parameters` | Read-heavy (input for injection tools). No new writes from these phases |
| `observations` | Read-heavy (tech_stack for context-aware routing). No new writes from these phases |
| `assets` | Read-heavy (target URLs). smuggler/host_header may write new assets if they discover additional attack surface |

No schema changes required. All tools use existing `lib_webbh` models.
