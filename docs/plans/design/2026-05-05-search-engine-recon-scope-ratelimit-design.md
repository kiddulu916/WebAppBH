# Search Engine Discovery, Scope Refactor & Rate Limiting — Design Document

**Date:** 2026-05-05
**WSTG Section:** 4.1.1 — Conduct Search Engine Discovery Reconnaissance for Information Leakage
**Worker:** `workers/info_gathering/`
**Depends on:** restructure-03-info-gathering, dashboard-ui-overhaul

---

## 1. Overview

This design covers four interconnected changes:

1. **Stage 1 overhaul** — full OWASP WSTG-INFO-01 coverage with 6 tools (up from 2)
2. **Scope system refactor** — 3-tier classification (in-scope / associated / undetermined), comprehensive wildcard support, 7-layer inference engine
3. **Campaign execution flow** — iterative multi-round expansion with automatic re-scanning of in-scope and associated discoveries
4. **Rate limiting overhaul** — stackable rules (req + bandwidth), Redis sliding window enforcement, global defaults + per-campaign overrides

Zero-cost constraint: no paid API subscriptions required. Search engine queries use direct multi-engine scraping. Shodan, Censys, and SecurityTrails use free API tiers and are optional (skip gracefully when keys aren't configured).

---

## 2. Stage 1 Redesign — search_engine_recon (WSTG 4.1.1)

### Updated tools list

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| DorkEngine | Rewrite | LIGHT | Multi-engine search scraper (Google, Bing, DuckDuckGo) with curated GHDB dork library. Round-robin queries across engines with 3-7s random delay. User-Agent rotation. Fallback redistribution on blocks. |
| ArchiveProber | Enhance | LIGHT | Existing Wayback CDX queries + cached content retrieval for sensitive file types (.env, .sql, .bak, .conf, .key). Limited to 20 cached page fetches per target. |
| CacheProber | New | LIGHT | Queries archive.ph for cached snapshots. Extracts captured URLs, fetches content for sensitive file types only. |
| ShodanSearcher | New | LIGHT | Queries Shodan free API for host data, open ports, banners, SSL certs, org/ASN info. Optional — skips if no SHODAN_API_KEY. |
| CensysSearcher | New | LIGHT | Queries Censys free API for infrastructure data, services, TLS certificates/SANs. Optional — skips if no CENSYS_API_ID/CENSYS_API_SECRET. |
| SecurityTrailsSearcher | New | LIGHT | Queries SecurityTrails free API for DNS records, subdomains, historical DNS, associated domains. Optional — skips if no SECURITYTRAILS_API_KEY. |

All 6 tools are LIGHT weight and run concurrently within Stage 1.

---

### 2.1 DorkEngine

**Search backends (round-robin rotation):**
- Google: `www.google.com/search`
- Bing: `www.bing.com/search`
- DuckDuckGo: `html.duckduckgo.com/html`

**Anti-detection:**
- Random delay between requests: 3-7 seconds (configurable)
- User-Agent rotation from a pool of 10 real browser strings
- Round-robin engine selection — each dork goes to one engine
- If an engine blocks (HTTP 429/503/CAPTCHA), redistribute remaining dorks to other engines

**Curated GHDB dork library — 8 categories, ~80 patterns:**

| Category | Example Patterns | Count |
|----------|-----------------|-------|
| Admin panels | `site:{domain} inurl:admin`, `intitle:"dashboard" site:{domain}` | ~10 |
| Config/backup files | `site:{domain} filetype:env`, `filetype:bak`, `filetype:conf`, `filetype:sql` | ~12 |
| Exposed credentials | `site:{domain} filetype:log password`, `inurl:credentials`, `intitle:"index of" .ssh` | ~10 |
| Error messages | `site:{domain} "fatal error"`, `"stack trace"`, `"SQL syntax"` | ~8 |
| Staging/test environments | `site:{domain} inurl:staging`, `inurl:dev`, `inurl:test`, `inurl:uat` | ~8 |
| Sensitive directories | `site:{domain} intitle:"index of"`, `inurl:/.git`, `inurl:/.svn` | ~10 |
| Sensitive documents | `site:{domain} filetype:pdf confidential`, `filetype:xlsx`, `filetype:docx` | ~10 |
| Login/auth pages | `site:{domain} inurl:login`, `inurl:signup`, `intitle:"forgot password"` | ~10 |

**Output:** Each discovered URL saved as `Asset` with `asset_type="url"`, `source_tool="dork_engine"`, plus `Observation` with the dork query that found it and the result snippet text.

---

### 2.2 ArchiveProber (enhanced)

**Existing behavior (unchanged):** Queries Wayback Machine CDX API for historical URLs.

**New behavior:** For interesting finds matching sensitive file extensions (`.env`, `.sql`, `.bak`, `.conf`, `.key`, `.pem`, `.log`, `.xml`), fetch the actual cached snapshot from `https://web.archive.org/web/{timestamp}/{url}`.

- Limit: 20 cached page fetches per target
- Save as `Observation` with `observation_type="cached_content"`: URL, timestamp, content snippet (first 2KB), matched pattern
- No full page bodies stored in DB — just enough to confirm the finding is worth investigating

---

### 2.3 CacheProber (new)

- Queries `archive.ph/newest/{domain}` to check for snapshots
- Extracts list of captured URLs from archive.ph results page
- Same sensitive-file filter as ArchiveProber — only fetch content for matching extensions
- Save results as `Asset` (URLs) and `Observation` (cached content metadata)

---

### 2.4 ShodanSearcher (new, optional)

**API:** `https://api.shodan.io` with `?key={SHODAN_API_KEY}`

**Queries:**
1. `GET /dns/resolve?hostnames={domain}` — resolve domain to IPs
2. `GET /shodan/host/{ip}` — for each resolved IP: open ports, services, banners, OS, org

**Data saved:**
- Open ports → `Asset` with `asset_type="ip"`, port/protocol metadata
- Service banners → `Observation` with tech_stack, service name, version, banner text
- SSL cert info → `Observation` with cert subject, issuer, expiry
- Org/ISP/ASN → `Observation` on the IP asset

**Rate limiting:** 1 request/second (`asyncio.sleep(1)` between calls).

**Skip behavior:** If `SHODAN_API_KEY` not set → `logger.info("No Shodan API key configured, skipping")` → return `None`.

---

### 2.5 CensysSearcher (new, optional)

**API:** `https://search.censys.io/api/v2` with HTTP Basic Auth (`CENSYS_API_ID:CENSYS_API_SECRET`)

**Queries:**
1. `GET /v2/hosts/search?q={domain}` — hosts associated with domain
2. `GET /v2/hosts/{ip}` — services and certificates per host

**Data saved:**
- Discovered IPs → `Asset` with `asset_type="ip"`, `source_tool="censys"`
- Services per IP → `Observation` with port, protocol, service name, software/version
- TLS certificates → `Observation` with subject names, SANs (can reveal additional subdomains)
- Autonomous system info → `Observation` with ASN, org name

**Rate limiting:** `asyncio.sleep(0.5)` between calls. Free tier: 250 queries/day.

**Skip behavior:** If `CENSYS_API_ID` or `CENSYS_API_SECRET` not set → skip with log message → return `None`.

---

### 2.6 SecurityTrailsSearcher (new, optional)

**API:** `https://api.securitytrails.com/v1` with `apikey` header set to `SECURITYTRAILS_API_KEY`

**Queries:**
1. `GET /v1/domain/{domain}` — current DNS records (A, AAAA, MX, NS, TXT, SOA)
2. `GET /v1/domain/{domain}/subdomains` — all known subdomains from historical data
3. `GET /v1/history/{domain}/dns/a` — historical A records (past IPs, infrastructure changes)
4. `GET /v1/domain/{domain}/associated` — domains sharing infrastructure (same IP, mail server, nameserver)

**Data saved:**
- Current DNS records → `Observation` with full record set per domain
- Subdomains → `Asset` with `asset_type="subdomain"`, `source_tool="securitytrails"`
- Historical IPs → `Observation` with timeline of IP changes (reveals shadow infrastructure)
- Associated domains → `Asset` with `asset_type="domain"`, classified through scope checker

**Value vs existing tools:** Subfinder/Amass already query SecurityTrails for subdomains, but this tool also pulls historical DNS and associated domains — neither available through subfinder/amass. Historical IPs reveal dev/staging servers that moved but still exist.

**Rate limiting:** `asyncio.sleep(2)` between calls. Free tier: 50 queries/month.

**Skip behavior:** If `SECURITYTRAILS_API_KEY` not set → skip with log message → return `None`.

---

## 3. Scope System Refactor

### 3.1 Three-tier classification

| Tier | Meaning | Auto-scanned? |
|------|---------|---------------|
| `in-scope` | Directly matches a scope entry | Yes |
| `associated` | Doesn't match directly, but provably linked to an in-scope asset | Yes |
| `undetermined` | No direct match AND no provable link | Held for manual approval |

### 3.2 Wildcard pattern support (both in-scope and out-of-scope)

**Domain wildcards:**

| Pattern | Matches |
|---------|---------|
| `*.example.com` | Any subdomain of example.com |
| `**.example.com` | Alias for `*.example.com` |
| `example.com` | Exact domain |

**Path wildcards:**

| Pattern | Matches |
|---------|---------|
| `example.com/api/v1/*` | Any path under /api/v1/ |
| `example.com/api/v1/*.json` | Any .json file under /api/v1/ |
| `example.com/api/v1/file.*` | file with any extension |
| `example.com/*/config` | Any single path segment before /config |
| `**/api/v1/*` | Any domain + any path prefix before /api/v1/ |
| `example.com/**/secret` | Matches example.com/a/secret AND example.com/a/b/c/secret |

`**` works recursively like gitignore — matches any number of intermediate path segments.

**IP wildcards:**

| Pattern | Matches |
|---------|---------|
| `10.0.0.1` | Exact IP |
| `192.168.0.0/16` | CIDR range |
| `123.*.123.123` | Any value in second octet |
| `123.123.*.*` | Any value in last two octets |
| `*.*.123.123` | Any value in first two octets |
| `*.123.*.123` | Any combination of wildcard octets |
| `123.*.*.*` | Any combination of wildcard octets |
| `*.*.*.*` | All IPs (any octet can be `*`) |

Any octet position can be `*`, in any combination.

**Evaluation order:** Out-of-scope patterns are always checked first. If an asset matches any out-of-scope pattern, it's excluded regardless of in-scope matches.

### 3.3 Seven-layer inference engine

Layers evaluated in order — first match wins. Only if ALL 7 layers fail does an asset become `undetermined`.

| Layer | Method | Result | Example |
|-------|--------|--------|---------|
| 1. Direct match | Wildcard domain, exact domain, CIDR range, exact IP, regex, path glob | `in-scope` | `api.t-mobile.com` matches `*.t-mobile.com` |
| 2. DNS resolution | Found IP resolves (forward or reverse) to an in-scope domain | `associated` | `52.10.30.40` → rDNS → `lb1.t-mobile.com` |
| 3. TLS/SSL SANs | Certificate on found IP includes in-scope domain in Subject or SANs | `associated` | IP's cert has `SAN: *.t-mobile.com` |
| 4. HTTP hosting | Found IP returns content with Host matching in-scope domain, or redirects to one | `associated` | `52.10.30.40` redirects to `t-mobile.com` |
| 5. WHOIS/ASN | Found IP belongs to same ASN or registered org as known in-scope IPs | `associated` | Same AS number as other confirmed IPs |
| 6. Header linkage | CORS headers, Location redirects, CSP reference in-scope domains | `associated` | `Access-Control-Allow-Origin: https://t-mobile.com` |
| 7. Discovered-from | Asset was directly discovered by scanning an in-scope asset (parent chain exists) | `associated` | Subdomain found in JS file on in-scope page |

### 3.4 Relationship tracking

- Every associated asset stores `associated_with_id` → the asset ID it's linked to
- Association method stored: `"dns_resolution"`, `"tls_san"`, `"same_asn"`, `"http_hosting"`, `"header_linkage"`, `"discovered_from"`
- Creates a traversable graph: `t-mobile.com → api.t-mobile.com → 52.10.30.40 → internal.t-mobile.com`
- Dashboard visualizes these chains on the assets page

### 3.5 Database changes

`Asset` model additions:
- `scope_classification` — enum: `in-scope`, `associated`, `undetermined`, `out-of-scope`
- `associated_with_id` — FK to `assets.id` (nullable, self-referential)
- `association_method` — varchar (nullable): how the association was determined

---

## 4. Campaign Execution Flow

### 4.1 Multi-round iterative expansion

**Round 1 — Initial sweep:**
1. Run full pipeline on `base_domain` (e.g., `t-mobile.com`)
2. Run full pipeline on each additional domain/IP in the in-scope list
3. Runs governed by pipeline queue concurrency cap (default 3 concurrent pipelines)
4. After all complete → classify every discovered asset through the 7-layer scope checker

**Round 2+ — Expansion:**
1. Gather all newly discovered `in-scope` and `associated` assets not yet scanned
2. Queue each for a full pipeline run
3. After all complete → classify new discoveries
4. Repeat until no new in-scope or associated assets are discovered (convergence)

**Undetermined assets:**
- Held in queue, surfaced on assets page
- User marks as in-scope → auto-queued for next pipeline run
- User marks as out-of-scope → excluded from future scans

### 4.2 Safeguards

| Safeguard | Default | Purpose |
|-----------|---------|---------|
| Max rounds | 5 | Prevents infinite expansion loops |
| Max assets per round | 500 | Pauses for review if too many new targets discovered |
| Deduplication | Always on | Asset never scanned twice (tracked via job_state) |

### 4.3 Pipeline events

- `ROUND_COMPLETE` — summary of found assets, what's queued next
- `EXPANSION_PAUSED` — safeguard triggered, waiting for user review
- `CAMPAIGN_COMPLETE` — convergence reached, no new assets to scan

### 4.4 Concurrency control

| Layer | What it controls | Mechanism |
|-------|-----------------|-----------|
| Pipeline queue | How many full pipeline instances run at once | Configurable cap (default 3). Redis-backed FIFO queue |
| Global rate limiter | Cross-pipeline rate limits for shared resources | Redis sliding window token buckets. All pipeline instances share the same limiter |

**Global rate limiter buckets:**

| Bucket | Default limit | Shared across |
|--------|--------------|---------------|
| `search_engines` | 1 query per 5 seconds | All DorkEngine instances |
| `shodan_api` | 1 request per second | All ShodanSearcher instances |
| `censys_api` | 1 request per 2 seconds | All CensysSearcher instances |
| `securitytrails_api` | 1 request per 2 seconds | All SecurityTrailsSearcher instances |
| `target_network` | Campaign rate limit rules | All tools hitting target infrastructure |

---

## 5. Flexible Rate Limiting

### 5.1 Rule format

Each rule is a pair: `amount` + `unit`.

**Request-based:**

| Format | Example | Meaning |
|--------|---------|---------|
| `req/s` | `50 req/s` | 50 requests per second |
| `req/min` | `500 req/min` | 500 requests per minute |
| `req/hr` | `10000 req/hr` | 10,000 requests per hour |
| `req/day` | `50000 req/day` | 50,000 requests per day |
| `req/Ns` | `100 req/5s` | 100 requests per custom window |

**Bandwidth-based (max unit: MB):**

| Format | Example | Meaning |
|--------|---------|---------|
| `bytes/s` | `500 bytes/s` | 500 bytes per second |
| `KB/s` | `100 KB/s` | 100 kilobytes per second |
| `MB/s` | `5 MB/s` | 5 megabytes per second |
| `KB/Ns` | `500 KB/5s` | 500 kilobytes per 5 seconds |
| `MB/min` | `100 MB/min` | 100 megabytes per minute |
| `MB/hr` | `500 MB/hr` | 500 megabytes per hour |

### 5.2 Stackable rules

Users can add multiple rules. All are enforced simultaneously — the most restrictive one wins at any given moment.

Example: `50 req/s` AND `5 MB/s` AND `10000 req/hr` — burst control plus sustained cap plus bandwidth limit.

### 5.3 Enforcement — Redis sliding window counters

- Each rule gets its own Redis counter key: `ratelimit:{campaign_id}:{rule_hash}`
- Before any target-facing request, the tool checks ALL active rules
- If ANY rule is exceeded → request waits until that window slides open
- Byte-based rules track response body size after each request
- All pipeline instances share the same Redis counters

### 5.4 Storage

- Campaign model: `rate_limits: [{"amount": 50, "unit": "req/s"}, {"amount": "5", "unit": "MB/s"}]`
- Global defaults configurable on settings page (apply when campaign doesn't specify custom rules)
- Per-campaign rules override global defaults
- Pre-set default: `50 req/s`

### 5.5 UI — Rate limit builder

Present in both settings page (global defaults) and campaign creation (per-campaign overrides).

- Each rule is a row: amount input + unit dropdown
- "Add rule" button to stack additional rules
- "Remove" button per row (except last — must have at least one rule)
- Campaign creation pre-populates from global defaults, user can modify/add/remove

---

## 6. API Key Management

### 6.1 Supported keys

| Service | Env vars | Free tier |
|---------|----------|-----------|
| Shodan | `SHODAN_API_KEY` | Basic host lookups, 1 req/s |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` | 250 queries/day |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | 50 queries/month |

### 6.2 Orchestrator endpoints

**`GET /api/v1/config/api_keys`** — returns status (never actual keys):
```json
{
  "keys": {
    "shodan": true,
    "censys": true,
    "securitytrails": false
  }
}
```
`censys` is `true` only if BOTH `CENSYS_API_ID` and `CENSYS_API_SECRET` are set.

**`PUT /api/v1/config/api_keys`** — accepts any combination:
```json
{
  "shodan_api_key": "...",
  "censys_api_id": "...",
  "censys_api_secret": "...",
  "securitytrails_api_key": "..."
}
```
Only non-empty fields are written. Empty strings do not overwrite existing keys. Persisted to `/shared/config/.env.intel`.

### 6.3 Dashboard — Settings page

- "API Keys" section shows all 3 services (5 fields total)
- Key already set → green status badge "API key configured" + "Change" button to reveal input
- Key not set → normal text input with placeholder
- Password inputs with show/hide toggle (Eye/EyeOff icons)
- Save/Cancel buttons, only sends non-empty fields

### 6.4 Dashboard — ScopeBuilder Step 0

- Same 3 services with same status badge / input toggle behavior
- Lighter styling (status badges, no show/hide toggle)
- Keys saved before target creation on submit
- Only sends non-empty fields via conditional spread

### 6.5 docker-compose.yml

Add to orchestrator + info_gathering worker environment:
```yaml
CENSYS_API_ID: ${CENSYS_API_ID:-}
CENSYS_API_SECRET: ${CENSYS_API_SECRET:-}
```
(Shodan and SecurityTrails already present.)

---

## 7. Assets Page Changes

### 7.1 Classification filter

- New filter dropdown in filter bar: `Classification` → `All` | `In-scope` | `Associated` | `Undetermined` | `Out-of-scope`
- Default view: `All`
- `Undetermined` tab shows count badge (e.g., "Undetermined (12)")

### 7.2 Undetermined triage

- Each undetermined row shows: asset value, type, how discovered, which asset it was discovered from
- Action buttons per row: "Mark In-scope" | "Mark Out-of-scope"
- Select-all checkbox in table header — toggles all row checkboxes
- Bulk select via row checkboxes + bulk action dropdown: "Set selected → In-scope" | "Set selected → Out-of-scope"
- Marking in-scope → asset auto-queues for pipeline run
- Marking out-of-scope → asset excluded, added to out-of-scope pattern list

### 7.3 Association chain display

- Associated assets show link icon + clickable parent: "Associated with `api.t-mobile.com` via `dns_resolution`"
- Clicking parent navigates to that asset's detail view
- Asset detail page shows chain visualization: `t-mobile.com → api.t-mobile.com → 52.10.30.40`
- Chain built by walking `associated_with_id` relationships

---

## 8. File Changes Summary

### New files
- `workers/info_gathering/tools/cache_prober.py`
- `workers/info_gathering/tools/shodan_searcher.py`
- `workers/info_gathering/tools/censys_searcher.py`
- `workers/info_gathering/tools/securitytrails_searcher.py`

### Modified files — Worker
- `workers/info_gathering/tools/dork_engine.py` — full rewrite
- `workers/info_gathering/tools/archive_prober.py` — cached content retrieval
- `workers/info_gathering/pipeline.py` — Stage 1 tools list update
- `workers/info_gathering/concurrency.py` — register new tools as LIGHT
- `workers/info_gathering/main.py` — multi-round expansion logic

### Modified files — Shared library
- `shared/lib_webbh/scope.py` — 3-tier classification, wildcard engine, 7-layer inference
- `shared/lib_webbh/database.py` — Asset model additions (scope_classification, associated_with_id, association_method)

### Modified files — Orchestrator
- `orchestrator/main.py` — extend api_keys endpoints for Censys, rate limit model changes

### Modified files — Dashboard
- `dashboard/src/app/settings/page.tsx` — Censys fields, rate limit builder
- `dashboard/src/components/campaign/ScopeBuilder.tsx` — Censys fields, wildcard scope input, rate limit builder
- `dashboard/src/lib/api.ts` — updateApiKeys type extension, rate limit types
- Assets page component(s) — classification filter, triage UI, association chains, select-all checkbox

### Modified files — Infrastructure
- `docker-compose.yml` — CENSYS_API_ID, CENSYS_API_SECRET env vars
