---
name: wstg-info-09-alignment
description: Align info_gathering stage 8 with merged WSTG-INFO-09 CMS fingerprinting and realign stage 9 to WSTG-INFO-10 with dedicated architecture probe tools
metadata:
  type: design
---

# WSTG-INFO-09 Alignment Design

## Context

The OWASP WSTG has consolidated **INFO-09 "Fingerprint Web Application"** into **INFO-08 "Fingerprint Web Application Framework"**. The distinction INFO-09 originally drew was between *framework-level* fingerprinting (Django, Rails) and *application-level* fingerprinting (CMS vendor and version — WordPress 6.4.2, Drupal 10.1, Joomla 4.3). Both detection scopes now live under INFO-08.

The current codebase has two misalignments as a result:

1. **Stage 8 (`fingerprint_framework`, `4.1.8`)** covers INFO-08's framework detection well but lacks the application-level CMS version-pinning that INFO-09 originally prescribed (BlindElephant-style hash matching).
2. **Stage 9 (`map_architecture`, `4.1.9`)** carries the wrong `section_id` — the tools it runs (`Waybackurls`, `ArchitectureModeler`) are INFO-10 (Map Application Architecture) work, not INFO-09 work.

## Approach

Keep the 12-stage pipeline structure intact. No stage names change. Two focused fixes:

- Extend stage 8 with a `CMSFingerprinter` tool that covers the merged INFO-09 scope.
- Fix stage 9's `section_id` from `"4.1.9"` to `"4.1.10"` and add four dedicated INFO-10 architecture probe tools alongside the existing `Waybackurls` and `ArchitectureModeler`.

---

## Stage 8 Extension — `CMSFingerprinter`

### Purpose

Satisfy the WSTG-INFO-09 scope (now merged into INFO-08): identify the deployed CMS by name and pin its version using BlindElephant-style static asset hash matching.

### Fingerprint Database

A bundled JSON file at `workers/info_gathering/data/cms_fingerprints.json` with this schema:

```json
{
  "wordpress": {
    "probe_paths": [
      "/wp-login.php",
      "/wp-includes/js/jquery/jquery.js",
      "/wp-includes/css/buttons.css"
    ],
    "versions": {
      "6.4.2": {
        "/wp-includes/js/jquery/jquery.js": "abc123deadbeef..."
      },
      "6.3.1": { ... }
    }
  },
  "drupal": {
    "probe_paths": [
      "/core/CHANGELOG.txt",
      "/core/misc/drupal.js"
    ],
    "versions": { ... }
  },
  "joomla": { ... },
  "magento": { ... },
  "typo3": { ... }
}
```

Initial coverage: WordPress, Drupal, Joomla, Magento, Typo3. The database is a static file — no external service dependency.

### Detection Algorithm

1. For each CMS in the database, fetch each `probe_path` via HTTP GET.
2. A 200 response on any probe path confirms CMS presence.
3. For confirmed CMSes, MD5-hash the response body of each versioned file and look it up in the `versions` table.
4. For each candidate version in the database, compute a confidence score: `hashes_matched_for_version / total_hashes_defined_for_version`. Report the version whose score is highest, provided ≥ 1 hash matched for it.
5. If presence is confirmed but no hash matches any version, report the CMS with version `"unknown"`.

### Output

Saves an `Observation` with:
```python
{
  "_probe": "cms_fingerprinter",
  "_source": "cms_fingerprinter",
  "cms": "<name>",           # e.g. "wordpress"
  "version": "6.4.2",        # or "unknown"
  "confidence": 0.75,        # fraction of hash probes matched
  "confirmed_paths": [...]   # probe paths that returned 200
}
```

The `FrameworkFingerprintAggregator` already scores the `cms` slot — `CMSFingerprinter` signals feed directly into the existing aggregation path without changes to the aggregator.

### Tool Weight

`LIGHT` — pure async HTTP, no subprocess.

### Updated Stage 8 Tool List

```python
Stage(name="fingerprint_framework", section_id="4.1.8", tools=[
    Wappalyzer, CookieFingerprinter, Webanalyze,
    HeaderFrameworkProbe, MetaGeneratorProbe, FrameworkFileProber,
    CMSFingerprinter,
])
```

---

## Stage 9 Realignment — `map_architecture` to `4.1.10`

### `section_id` Fix

Change `section_id="4.1.9"` → `section_id="4.1.10"` on the `map_architecture` Stage object. This is the only change to stage 9's identity — the name `map_architecture` is correct and stays.

### Four New Architecture Probe Tools

All four are `LIGHT` weight (header inspection + lightweight async HTTP, no subprocesses).

#### `CDNProbe`

Resolves the target's A/AAAA records, then performs an ASN lookup via the `ipwhois` library (no external binary). Matches ASN org name against a known CDN ASN table (Cloudflare AS13335, Akamai AS20940, Fastly AS54113, Amazon CloudFront AS16509, Sucuri AS30148).

Output observation:
```python
{"_probe": "cdn_probe", "provider": "cloudflare", "ips": [...], "asn": "AS13335"}
```

#### `LoadBalancerProbe`

Sends 5 sequential HEAD requests to the target and inspects:
- **Cookie patterns**: `Set-Cookie` header for known LB cookies — `BIGipServer*` (F5), `AWSALB` / `AWSALBCORS` (AWS ALB), `X-Forwarded-Server` (HAProxy).
- **Header variance**: checks whether `X-Served-By` or `Via` values differ across the 5 responses.
- **TTL jitter**: variance in `X-Cache` or `Age` header values across responses.

Output observation:
```python
{"_probe": "load_balancer_probe", "detected": true, "vendor": "f5", "signals": [...]}
```

#### `ServerlessProbe`

Single HEAD + GET request; inspects response headers for platform markers:

| Platform | Headers |
|---|---|
| AWS Lambda | `x-amz-request-id`, `x-amz-executed-version` |
| Azure Functions | `x-ms-request-id`, `x-azure-ref` |
| Google Cloud Functions | `function-execution-id`, `x-cloud-trace-context` |
| Vercel | `x-vercel-id` |
| Netlify | `x-nf-request-id` |

No active payloads — pure header inspection.

Output observation:
```python
{"_probe": "serverless_probe", "platform": "aws_lambda", "headers_matched": [...]}
```

#### `ReverseProxyProbe`

Detects proxy layers by comparing the `Server` header value against proxy-indicative headers:
- `Via` header present and differs from `Server` value
- `X-Forwarded-For` or `X-Real-IP` present
- Explicit proxy headers: `X-Varnish`, `CF-Ray`, `X-Cache: HIT`

A mismatch (e.g., `Server: Apache` with `Via: Varnish`) indicates a reverse proxy in front.

Output observation:
```python
{"_probe": "reverse_proxy_probe", "detected": true, "proxy_type": "varnish", "signals": [...]}
```

### Updated Stage 9 Tool List

```python
Stage(name="map_architecture", section_id="4.1.10", tools=[
    Waybackurls, ArchitectureModeler,
    CDNProbe, LoadBalancerProbe, ServerlessProbe, ReverseProxyProbe,
])
```

---

## Three-Layer Coherence

No stage names change, so `playbooks.py` (`PIPELINE_STAGES` dict) requires **no edits**.

### `pipeline.py`

- Add imports for `CMSFingerprinter`, `CDNProbe`, `LoadBalancerProbe`, `ServerlessProbe`, `ReverseProxyProbe`
- Append `CMSFingerprinter` to the stage 8 `tools` list
- Append four new probes to the stage 9 `tools` list
- Fix `section_id="4.1.9"` → `"4.1.10"` on `map_architecture`

### `dashboard/src/lib/worker-stages.ts`

- Fix `sectionId: "WSTG-INFO-09"` → `"WSTG-INFO-10"` on the `map_architecture` entry

### `workers/info_gathering/concurrency.py`

Add five `LIGHT` entries to `TOOL_WEIGHTS`:
```python
"CMSFingerprinter":   "LIGHT",
"CDNProbe":           "LIGHT",
"LoadBalancerProbe":  "LIGHT",
"ServerlessProbe":    "LIGHT",
"ReverseProxyProbe":  "LIGHT",
```

---

## New Files Summary

| File | Purpose |
|---|---|
| `workers/info_gathering/tools/cms_fingerprinter.py` | BlindElephant-style CMS detection tool |
| `workers/info_gathering/data/cms_fingerprints.json` | Bundled fingerprint database (paths + MD5 hashes per version) |
| `workers/info_gathering/tools/cdn_probe.py` | CDN detection via ASN lookup |
| `workers/info_gathering/tools/load_balancer_probe.py` | LB cookie/header variance detection |
| `workers/info_gathering/tools/serverless_probe.py` | Serverless platform header detection |
| `workers/info_gathering/tools/reverse_proxy_probe.py` | Reverse proxy layer detection |

## Modified Files Summary

| File | Change |
|---|---|
| `workers/info_gathering/pipeline.py` | Add imports, extend stage 8 + 9 tool lists, fix section_id |
| `workers/info_gathering/concurrency.py` | Add 5 LIGHT tool weight entries |
| `dashboard/src/lib/worker-stages.ts` | Fix sectionId WSTG-INFO-09 → WSTG-INFO-10 |

## Out of Scope

- Changes to `playbooks.py` (stage names unchanged)
- Changes to `FrameworkFingerprintAggregator` (cms slot already handled)
- New e2e test file (existing `test_info_gathering.py` covers stage execution; individual tool assertions are out of scope for this design)
- Updating the CMS fingerprint database with real MD5 hashes (a follow-on data task)
