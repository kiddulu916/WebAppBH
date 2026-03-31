# WSTG-Aligned Restructure — 03 Info Gathering Worker

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview
**WSTG Section:** 4.1 Information Gathering
**Worker Directory:** `workers/info_gathering/`
**Queue:** `info_gathering_queue`
**Trigger:** Target created (no dependencies)

---

## Overview

The info_gathering worker is the entry point for all testing. It runs first against every seed target and produces the asset inventory that all downstream workers depend on. It absorbs the current `recon_core` worker and adds tools for WSTG sections that were previously uncovered (search engine discovery, metafile review, webpage content review).

After this worker completes, the `TargetExpander` (see restructure-08) collects all discovered subdomains, vhosts, and live URLs and creates child target records that each run through the remaining WSTG pipeline.

---

## Pipeline Stages

### Stage 1: search_engine_discovery (Section 4.1.1)

**Objective:** Identify sensitive design and configuration information indexed by search engines and public data sources.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| DorkEngine | New | LIGHT | Queries Google, Bing, and Shodan using advanced search operators (dorking). Generates dork patterns from the target domain: `site:target.com filetype:config`, `site:target.com filetype:bak`, `site:target.com inurl:admin`, `site:target.com ext:sql`, `site:target.com ext:env`. Rate-limited to respect search engine ToS (1 query/5 seconds). Parses result URLs and stores as Location records. |
| ArchiveProber | New | LIGHT | Queries the Wayback Machine CDX API for historical snapshots of the target. Identifies pages that existed in the past but are no longer linked — old admin panels, deprecated API endpoints, removed configuration pages. Compares historical paths against current sitemap to find orphaned content. Stores discovered paths as Location records with `source="archive"`. |

**Outputs:** Location records (discovered URLs from search results and archives).

**Concurrency:** Both tools are LIGHT weight — run concurrently.

---

### Stage 2: webserver_fingerprinting (Section 4.1.2)

**Objective:** Identify the web server software, version, and supporting infrastructure (load balancers, WAFs, reverse proxies).

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| Nmap | Carried (recon_core) | HEAVY | Service version detection (`-sV`) on discovered ports. Identifies web server (Apache, Nginx, IIS, etc.) and version. OS fingerprinting (`-O`) when possible. Results stored as Observation records with `observation_type="server_fingerprint"`. |
| WhatWeb | Carried (recon_core) | LIGHT | HTTP-level fingerprinting via response headers, HTML content, and cookies. Identifies `Server`, `X-Powered-By`, `X-AspNet-Version` headers. Detects load balancers (different Server headers across requests) and WAFs (blocked response patterns). Aggression level 3 (stealthy + redirect following). |
| Httpx | Carried (recon_core) | LIGHT | Probes all discovered hosts for HTTP/HTTPS liveness. Extracts response titles, status codes, content lengths, TLS certificate info. Flags hosts with both HTTP and HTTPS (mixed content potential). Stores as Asset records with enriched metadata. |

**Outputs:** Observation records (server fingerprints), enriched Asset records.

**Concurrency:** Nmap is HEAVY (1 concurrent), WhatWeb and Httpx are LIGHT (run in parallel).

---

### Stage 3: metafile_review (Section 4.1.3)

**Objective:** Extract information from webserver metafiles that reveal hidden paths, API endpoints, or security configuration.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| MetafileParser | New | LIGHT | Fetches and parses standard metafiles for each discovered host: `robots.txt` (Disallow entries reveal hidden paths), `sitemap.xml` (full URL inventory), `.well-known/security.txt` (contact info, PGP keys, disclosure policies), `.well-known/openid-configuration` (OAuth/OIDC endpoints), `humans.txt`, `crossdomain.xml`, `clientaccesspolicy.xml`. Each discovered path stored as a Location record. Disallowed paths flagged for priority testing by downstream workers — developers hide what they want to protect. |

**Outputs:** Location records (paths from metafiles), Observation records (security.txt contents, policy files).

**Concurrency:** Single LIGHT tool.

---

### Stage 4: application_enumeration (Section 4.1.4)

**Objective:** Discover all applications and subdomains hosted on the target infrastructure.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| Subfinder | Carried (recon_core) | LIGHT | Passive subdomain enumeration from 40+ public sources (Certificate Transparency logs, DNS datasets, Chaos dataset, VirusTotal, SecurityTrails, etc.). Requires API keys for premium sources (configured in target profile). Stores as Asset records with `asset_type="subdomain"`. |
| Assetfinder | Carried (recon_core) | LIGHT | Complementary passive subdomain discovery. Queries different source set than Subfinder (Facebook CT, Certspotter, HackerTarget). Fast, lightweight, good for catching subdomains Subfinder misses. |
| AmassPassive | Carried (recon_core) | HEAVY | OWASP Amass in passive mode. Deepest source coverage — DNS brute-force disabled, only passive data collection. Queries CIRCL, DNSDB, URLScan, Pastebin scrapes. Slower but most thorough passive source. |
| AmassActive | Carried (recon_core) | HEAVY | OWASP Amass in active mode. DNS brute-force with permutation wordlists, zone transfers attempted, DNS wildcard detection. Finds subdomains that passive sources miss. Absorbs Knockpy's DNS brute-force capability. |
| Massdns | Carried (recon_core) | HEAVY | High-speed DNS resolver for validating discovered subdomains. Takes output from all subdomain tools, resolves A/AAAA/CNAME records, filters out non-resolving entries. Identifies CDN usage, shared hosting, and DNS misconfigurations. |
| VHostProber | New | LIGHT | Virtual host discovery via Host header manipulation. Sends requests with various Host headers (discovered subdomains, common vhost names) to each IP address. Detects applications that respond differently based on Host header — reveals hidden vhosts not in DNS. Response comparison by content length, title, and status code to filter false positives. |

**Outputs:** Asset records (subdomains, vhosts), DNS resolution data.

**Concurrency:** Subfinder, Assetfinder, VHostProber are LIGHT (concurrent). AmassPassive, AmassActive, Massdns are HEAVY (limited to 2 concurrent).

**Note:** This is the primary data source for the `TargetExpander`. All validated subdomains and vhosts from this stage become child targets.

---

### Stage 5: webpage_content_review (Section 4.1.5)

**Objective:** Extract sensitive information leaked in webpage HTML content — comments, metadata, version strings, email addresses, internal paths.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CommentHarvester | Carried (webapp_worker) | LIGHT | Crawls pages and extracts HTML comments (`<!-- ... -->`). Developers frequently leave debug notes, TODO items, internal URLs, credentials, and API keys in comments. Classifies findings by sensitivity: `credential` (contains password/key patterns), `internal_url` (contains internal hostnames/IPs), `debug` (contains debug/TODO text), `benign` (copyright notices, etc.). Stores sensitive comments as Observation records. |
| MetadataExtractor | New | LIGHT | Extracts information from HTML meta tags, HTTP headers in meta equiv, author tags, generator tags, and embedded JSON-LD structured data. Identifies: CMS versions (`<meta name="generator" content="WordPress 6.4">`), author identities, internal email addresses, API version strings, framework signatures. Compares against known version databases for CVE mapping. |

**Outputs:** Observation records (comments, metadata), potential credential findings.

**Concurrency:** Both LIGHT, run concurrently.

---

### Stage 6: entry_point_identification (Section 4.1.6)

**Objective:** Map every input vector where user data enters the application — forms, URL parameters, headers, cookies, API parameters.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| FormMapper | New | LIGHT | Crawls all discovered pages and extracts HTML forms. For each form: action URL, method (GET/POST), all input fields (name, type, default value, validation attributes), hidden fields, CSRF tokens, file upload fields. Stores each parameter as a Parameter record with `param_type` (query, body, file, hidden). Maps forms to their authentication requirements (login-gated vs public). |
| Paramspider | Carried (recon_core) | LIGHT | Mines web archives (Wayback Machine, Common Crawl) for historical URLs with parameters. Extracts unique parameter names across all archived URLs. Discovers parameters that may no longer be linked but still accepted by the server. Stores as Parameter records. |
| Httpx | Carried (recon_core) | LIGHT | Used in parameter extraction mode — crawls pages and extracts URL query parameters from links, JavaScript variables, and API calls embedded in page source. Complements FormMapper (which focuses on form fields) and Paramspider (which focuses on historical params). |

**Outputs:** Parameter records (all input vectors), Location records (form action URLs).

**Concurrency:** All LIGHT, run concurrently.

**Downstream impact:** This stage's output is critical for input_validation, authorization, session_mgmt, and business_logic workers. The more entry points discovered here, the more thorough the downstream testing.

---

### Stage 7: execution_path_mapping (Section 4.1.7)

**Objective:** Map the logical flow of data through the application — crawl all reachable paths, follow JavaScript-generated links, discover dynamically rendered content.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| Katana | Carried (recon_core) | HEAVY | ProjectDiscovery's web crawler. Headless browser mode for JavaScript-rendered content. Follows links, form submissions, and JavaScript redirects. Configurable depth (default 3), respects scope via ScopeManager. Outputs all discovered URLs with their response metadata. |
| Hakrawler | Carried (recon_core) | LIGHT | Fast Go-based crawler focused on link and endpoint extraction. Complements Katana — faster but less thorough on JavaScript-heavy sites. Extracts URLs from `href`, `src`, `action`, `data-*` attributes, and inline JavaScript. |

**Outputs:** Location records (all crawled paths), updated Parameter records (newly discovered params in URLs).

**Concurrency:** Katana is HEAVY (single), Hakrawler is LIGHT (runs concurrently with Katana).

---

### Stage 8: framework_fingerprinting (Section 4.1.8)

**Objective:** Identify the web application framework in use to inform downstream testing strategies (which injection types to prioritize, which default paths to check, which CVEs to test).

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| Wappalyzer | Carried (webapp_worker) | LIGHT | Technology detection via response patterns — HTML content, headers, JavaScript libraries, CSS frameworks. Identifies: frontend frameworks (React, Angular, Vue), backend frameworks (Django, Rails, Laravel, Express, Spring), CMS (WordPress, Drupal, Joomla), CDN/hosting, analytics, and ad networks. Stores as Observation records with `observation_type="tech_stack"`. |
| CookieFingerprinter | New | LIGHT | Analyzes cookie naming conventions to infer backend technology: `JSESSIONID` → Java, `PHPSESSID` → PHP, `ASP.NET_SessionId` → .NET, `connect.sid` → Node.js/Express, `_rails_session` → Ruby on Rails, `csrftoken` → Django, `laravel_session` → Laravel. Cross-references with Wappalyzer results for confirmation. Stores as Observation records. |

**Outputs:** Observation records (technology stack fingerprints).

**Concurrency:** Both LIGHT, run concurrently.

**Downstream impact:** Framework fingerprint determines:
- Which default credential sets to test (authentication worker stage 2)
- Which SQLi tamper scripts to use (input_validation worker stage 5)
- Which admin paths to brute-force (config_mgmt worker stage 5)
- Which template injection engines to target (input_validation worker stage 15)

---

### Stage 9: application_fingerprinting (Section 4.1.9)

**Objective:** Identify the specific web application (not just the framework) and its version for CVE mapping.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| Webanalyze | Carried (recon_core) | LIGHT | Identifies specific applications (WordPress 6.4.2, Jira 9.4.1, GitLab 16.5, etc.) from response content and headers. Uses Wappalyzer's technology database for matching. Provides version numbers where detectable. |
| Naabu | Carried (recon_core) | HEAVY | Port scanner used here for port-to-service mapping context. Maps open ports to known service defaults (8080 → Tomcat, 8443 → alternative HTTPS, 3000 → Node.js dev, 5000 → Flask dev, 9200 → Elasticsearch). Enriches the architecture model with service layer visibility. |

**Outputs:** Observation records (application versions, port-service mappings).

**Concurrency:** Webanalyze is LIGHT, Naabu is HEAVY. Run concurrently.

---

### Stage 10: architecture_mapping (Section 4.1.10)

**Objective:** Synthesize all gathered information into a conceptual model of the application's architecture — components, data flows, API boundaries, third-party integrations.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| Waybackurls | Carried (recon_core) | LIGHT | Extended to query multiple archive sources beyond Wayback Machine: AlienVault OTX, Common Crawl, URLScan.io. Absorbs Gauplus capabilities. Discovers historical API endpoints, removed features, legacy paths. Stores all unique URLs as Location records. Deduplicates against already-discovered paths from prior stages. |
| ArchitectureModeler | New | LIGHT | Aggregation tool — does not make new HTTP requests. Reads all Observation, Asset, Location, and Parameter records from stages 1-9 and builds a structured architecture model: identified components (frontend, API, database, CDN, WAF), data flow paths (user → CDN → WAF → app server → database), third-party integrations (payment gateways, auth providers, analytics). Stores the model as an Observation record with `observation_type="architecture_model"`. This model is consumed by downstream workers for context-aware testing. |

**Outputs:** Location records (historical URLs), Observation records (architecture model).

**Concurrency:** Both LIGHT, run concurrently.

---

## Concurrency Configuration

```python
# workers/info_gathering/concurrency.py

HEAVY_LIMIT = 2    # Max concurrent HEAVY tools (Nmap, Amass, Massdns, Katana, Naabu)
LIGHT_LIMIT = cpu_count()  # Max concurrent LIGHT tools

TOOL_WEIGHTS = {
    "DorkEngine": "LIGHT",
    "ArchiveProber": "LIGHT",
    "Nmap": "HEAVY",
    "WhatWeb": "LIGHT",
    "Httpx": "LIGHT",
    "MetafileParser": "LIGHT",
    "Subfinder": "LIGHT",
    "Assetfinder": "LIGHT",
    "AmassPassive": "HEAVY",
    "AmassActive": "HEAVY",
    "Massdns": "HEAVY",
    "VHostProber": "LIGHT",
    "CommentHarvester": "LIGHT",
    "MetadataExtractor": "LIGHT",
    "FormMapper": "LIGHT",
    "Paramspider": "LIGHT",
    "Katana": "HEAVY",
    "Hakrawler": "LIGHT",
    "Wappalyzer": "LIGHT",
    "CookieFingerprinter": "LIGHT",
    "Webanalyze": "LIGHT",
    "Naabu": "HEAVY",
    "Waybackurls": "LIGHT",
    "ArchitectureModeler": "LIGHT",
}
```

---

## Checkpoint & Resume

Each stage checkpoints to `job_state` on completion. If the container crashes or is killed by the resource guard:

1. On restart, pipeline reads `job_state.current_stage_index`
2. Skips all completed stages
3. Resumes from the first incomplete stage
4. Within a stage, `last_tool_executed` identifies which tools already ran

Stage checkpoints:
```
current_stage_index=1, current_section_id="4.1.1"  → search_engine_discovery
current_stage_index=2, current_section_id="4.1.2"  → webserver_fingerprinting
...
current_stage_index=10, current_section_id="4.1.10" → architecture_mapping
```

---

## Base Tool Class

```python
# workers/info_gathering/base_tool.py

class InfoGatheringTool(ABC):
    """Abstract base for all info_gathering tools.

    Inherits from the shared BaseTool in lib_webbh.
    Adds info_gathering-specific helpers:
    - store_asset() for subdomain/host discovery
    - store_location() for URL/path discovery
    - store_observation() for fingerprint/metadata
    - store_parameter() for input vector discovery
    """
    worker_type = "info_gathering"

    @abstractmethod
    async def execute(self, target, assets):
        """Run the tool against the target.

        Args:
            target: Target record from database
            assets: List of Asset records discovered so far

        Returns:
            List of result dicts to be stored
        """
        pass
```

Tools that wrap external CLI commands (Subfinder, Nmap, Katana, etc.) implement `build_command()` and `parse_output()` as in the current recon_core pattern. Tools that are pure HTTP clients (FormMapper, MetafileParser, CookieFingerprinter, etc.) implement `execute()` directly.
