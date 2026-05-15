# WSTG-INFO-03: Webserver Metafiles — Stage 3 Full Build-Out

**Date:** 2026-05-14
**Section:** WSTG-INFO-03 (4.1.3)
**Worker:** `info_gathering`
**Status:** Approved

---

## Objective

Expand Stage 3 (`web_server_metafiles`) of the `info_gathering` pipeline to fully cover WSTG-INFO-03. The current implementation (`MetafileParser`) covers only 3 files with minimal parsing and has a broken `save_observation` call signature. This design completes the stage to cover all 6 metafile concerns defined by the WSTG and introduces a consistent tagging taxonomy so downstream workers can consume the intel.

---

## Scope

In scope:
- Expand `MetafileParser` to cover robots.txt, sitemap.xml (recursive), security.txt (both paths), humans.txt, and a curated `.well-known/` probe list
- Add new `MetaTagAnalyzer` tool to extract HTML `<meta>` tags from the page root
- Fix broken `save_observation` call signature in `MetafileParser`
- Define and apply a semantic tag taxonomy on all `Observation.tech_stack` payloads
- Wire both tools into Stage 3 in `pipeline.py`

Out of scope:
- Emitting `Vulnerability` records (findings are stored as intel observations, not confirmed vulns)
- Fixing `CommentHarvester`'s `save_observation` bug (separate concern)
- Directory listing of `.well-known/` (servers don't expose indexes; a curated probe list is used instead)
- Recursive sitemap expansion beyond one level of sitemap index

---

## Tag Taxonomy

All `Observation.tech_stack` payloads written by Stage 3 tools use semantic action-hint tags. Tags are strings in a `tags` list within the JSON payload.

### Intel tags (passive facts)

| Tag | Meaning |
|-----|---------|
| `intel:hidden-path` | A URL path disclosed by a metafile that isn't linked from the public surface |
| `intel:tech-stack` | Technology name, version, or framework hint found in metafile content |
| `intel:employee-pii` | Team member name, role, or contact info found in humans.txt or security.txt |
| `intel:security-contact` | Security disclosure contact (email, URL) from security.txt |
| `intel:site-structure` | Structural information about the app (OG URLs, sitemap hierarchy) |
| `intel:social-account` | Social media handle or account linked from meta tags |
| `intel:crawler-hint` | Robots META directive indicating intentionally hidden content |

### Candidate tags (action hints for downstream workers)

| Tag | Meaning | Likely consumer |
|-----|---------|----------------|
| `candidate:forced-browsing` | Path should be probed directly regardless of link exposure | `authorization` worker |
| `candidate:authn-bypass` | Path looks like an auth-protected area worth testing | `authentication` worker |
| `candidate:entry-point` | URL discovered via sitemap — candidate for input/parameter testing | `input_validation` worker |
| `candidate:version-disclosure` | Tech version hinted in meta tags — check CVEs | `config_mgmt` worker |

---

## Observation JSON Schema

Every observation written by Stage 3 tools follows this shape in `tech_stack`:

```json
{
  "source": "<source_id>",
  "intel_type": "<type>",
  "tags": ["<tag>", ...],
  "data": { ... }
}
```

| Field | Values |
|-------|--------|
| `source` | `robots_txt`, `sitemap_xml`, `security_txt`, `humans_txt`, `well_known_probe`, `meta_tag` |
| `intel_type` | `hidden_path`, `sitemap_url`, `security_contact`, `employee_info`, `tech_hint`, `well_known_endpoint`, `meta_robots`, `meta_social`, `meta_generator` |
| `tags` | One or more strings from the taxonomy above |
| `data` | Source-specific payload (see per-tool sections below) |

One `Observation` is written per discrete finding (one per disallowed path, one per sitemap batch, one per security.txt field group, etc.), all linked to `asset_id`.

---

## Tool 1: `MetafileParser` (expanded)

**File:** `workers/info_gathering/tools/metafile_parser.py`

### Execution flow

```
execute(target_id, asset_id, host, ...)
  └── asyncio.gather(
        _fetch_robots(),
        _fetch_sitemap(),
        _fetch_security_txt(),
        _fetch_humans_txt(),
        _probe_well_known(),
      )
```

All 5 fetches run concurrently. Each writes zero or more Observations. Missing files (non-200 or connection error) are silently skipped.

### robots.txt

Fetch `https://{host}/robots.txt`.

Parse:
- `Disallow` lines → path strings
- `Allow` lines → path strings
- `User-Agent` lines → agent strings
- `Sitemap` lines → URLs (fed into sitemap parser)

For each `Disallow` path:
- If path matches a sensitive prefix list (`/admin`, `/api`, `/internal`, `/config`, `/backup`, `/staging`, `/dev`, `/test`, `/dashboard`, `/manage`, `/private`, `/.git`, `/.env`) → tags include `candidate:forced-browsing` and `candidate:authn-bypass`
- All other non-empty paths → tag `intel:hidden-path`

Write one Observation per disallowed path (not batched — allows per-path querying by downstream workers). Write one Observation for the full `User-Agent` + `Allow` summary.

Example `data` payload for a disallowed path:
```json
{
  "source": "robots_txt",
  "intel_type": "hidden_path",
  "tags": ["intel:hidden-path", "candidate:forced-browsing", "candidate:authn-bypass"],
  "data": { "path": "/admin", "context": "Disallow" }
}
```

### sitemap.xml

Fetch `https://{host}/sitemap.xml` (and any `Sitemap:` refs found in robots.txt, deduped).

Parse `<loc>` entries. If a `<sitemap>` index element is found, fetch and expand those child sitemaps (one level deep, max 3 child sitemaps). Cap total URLs at 500.

Write one Observation per batch of 50 URLs (to avoid single oversized JSON blobs). Each observation:
```json
{
  "source": "sitemap_xml",
  "intel_type": "sitemap_url",
  "tags": ["candidate:entry-point", "intel:site-structure"],
  "data": { "urls": ["https://example.com/api/v1/users", ...], "batch": 0 }
}
```

### security.txt

Probe both `https://{host}/.well-known/security.txt` and `https://{host}/security.txt`. Use the first 200 response; if both return 200, prefer `.well-known/`.

Parse all RFC 9116 fields: `Contact`, `Policy`, `Encryption`, `Acknowledgments`, `Hiring`, `Expires`, `Canonical`, `Preferred-Languages`.

Write one Observation with all parsed fields grouped:
```json
{
  "source": "security_txt",
  "intel_type": "security_contact",
  "tags": ["intel:security-contact"],
  "data": {
    "contacts": ["mailto:security@example.com"],
    "policies": ["https://example.com/security"],
    "encryption": ["https://example.com/pgp-key.txt"],
    "hiring": ["https://example.com/jobs"],
    "expires": "2026-12-31T00:00:00Z"
  }
}
```

If `Hiring` is present, add `intel:employee-pii` to tags (indicates org structure / recruiting surface).

### humans.txt

Fetch `https://{host}/humans.txt`.

Parse section-delimited content. Sections are identified by `/* SECTION NAME */` headers. Extract:
- `/* TEAM */` section → names, roles, locations, social handles
- `/* THANKS */` section → third-party credits (tech hints)
- `/* SITE */` or `/* TECHNOLOGY */` section → explicit tech stack entries

Write one Observation:
```json
{
  "source": "humans_txt",
  "intel_type": "employee_info",
  "tags": ["intel:employee-pii", "intel:tech-stack"],
  "data": {
    "team": [{ "name": "Alice Smith", "role": "Lead Developer" }],
    "tech_credits": ["WordPress 6.4", "jQuery 3.7"],
    "raw_sections": { "SITE": "Standards: HTML5, CSS3" }
  }
}
```

Tags: always `intel:employee-pii` if team section present; add `intel:tech-stack` if tech credits present.

### .well-known/ probe

Probe a curated list of 15 IANA-registered `.well-known` paths. Record only those returning 2xx or 3xx.

Curated list:
```
openid-configuration
oauth-authorization-server
webfinger
change-password
mta-sts.txt
dmarc
pki-validation
apple-app-site-association
assetlinks.json
security.txt          # (already handled above — skip if already fetched)
nodeinfo
host-meta
caldav
carddav
acme-challenge/
```

For each responding path:
```json
{
  "source": "well_known_probe",
  "intel_type": "well_known_endpoint",
  "tags": ["intel:hidden-path"],
  "data": { "path": "/.well-known/openid-configuration", "status_code": 200 }
}
```

Auth-related paths (`openid-configuration`, `oauth-authorization-server`, `change-password`, `webfinger`) additionally get `candidate:authn-bypass`.

---

## Tool 2: `MetaTagAnalyzer` (new)

**File:** `workers/info_gathering/tools/meta_tag_analyzer.py`

### Execution flow

Fetch `https://{host}/` (single HTTP GET). Parse the HTML `<head>` for `<meta>` tags only. Ignore everything outside `<head>`. Use `html.parser` from stdlib (no external dependency).

### Three categories

**Robots directives** (`<meta name="robots" ...>`):
```json
{
  "source": "meta_tag",
  "intel_type": "meta_robots",
  "tags": ["intel:crawler-hint"],
  "data": { "directive": "noindex, nofollow" }
}
```

**Open Graph / Twitter Card** (`og:*`, `twitter:*`):
```json
{
  "source": "meta_tag",
  "intel_type": "meta_social",
  "tags": ["intel:social-account", "intel:site-structure"],
  "data": {
    "og_url": "https://example.com/",
    "og_site_name": "Example Corp",
    "twitter_creator": "@examplecorp",
    "twitter_site": "@examplecorp"
  }
}
```

**Generator / application hints** (`<meta name="generator">`, `<meta name="application-name">`, `<meta name="framework">`):
```json
{
  "source": "meta_tag",
  "intel_type": "meta_generator",
  "tags": ["intel:tech-stack", "candidate:version-disclosure"],
  "data": { "generator": "WordPress 6.4.2", "application_name": "MyApp" }
}
```

Only write Observations for categories where at least one tag was found. Missing `<head>` or no matching tags → no observation written.

---

## Pipeline Change

In `workers/info_gathering/pipeline.py`:

```python
from .tools.meta_tag_analyzer import MetaTagAnalyzer

STAGES = [
    ...
    Stage(name="web_server_metafiles", section_id="4.1.3", tools=[MetafileParser, MetaTagAnalyzer]),
    ...
]
```

Both tools receive `asset_id` and `host` via `kwargs` from `_run_stage` — no pipeline changes beyond the import and tools list.

---

## Bug Fix

The current `MetafileParser` calls:
```python
await self.save_observation(target_id, "metafile", {...}, "metafile_parser")
```

The correct call (matching `InfoGatheringTool.save_observation` signature):
```python
await self.save_observation(
    asset_id=asset_id,
    tech_stack={"source": "...", "tags": [...], "data": {...}},
    status_code=resp.status,
)
```

The new implementation uses `asset_id = kwargs.get("asset_id")` and `host = kwargs.get("host") or target.base_domain` at the top of `execute()`.

---

## Files Changed

| File | Change |
|------|--------|
| `workers/info_gathering/tools/metafile_parser.py` | Full rewrite |
| `workers/info_gathering/tools/meta_tag_analyzer.py` | New file |
| `workers/info_gathering/pipeline.py` | Add `MetaTagAnalyzer` import + Stage 3 tools list |

No new dependencies. `aiohttp` (already present), `asyncio` (stdlib), `html.parser` (stdlib), `re` (stdlib).

---

## Testing Notes

- Each parser method is pure (takes a string, returns structured data) — unit-testable without HTTP
- `execute()` methods are testable via `aiohttp` mocking with `aresponses` or `pytest-aiohttp`
- Stage 3 e2e: assert that after pipeline run, `observations` table contains rows with `tech_stack->>'source'` in `('robots_txt', 'sitemap_xml', 'security_txt', 'humans_txt', 'well_known_probe', 'meta_tag')` for target
