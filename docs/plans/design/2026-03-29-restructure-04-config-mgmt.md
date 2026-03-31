# WSTG-Aligned Restructure — 04 Config Management Worker

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview, restructure-03-info-gathering
**WSTG Section:** 4.2 Configuration and Deployment Management Testing
**Worker Directory:** `workers/config_mgmt/`
**Queue:** `config_mgmt_queue`
**Trigger:** info_gathering complete

---

## Overview

The config_mgmt worker validates that the target's infrastructure and deployment are properly hardened. It absorbs:
- Cloud testing from `cloud_worker` (stage 11)
- Network infrastructure testing from `network_worker` (stage 1)
- Subdomain takeover from `recon_core` (stage 10)
- Directory/file discovery from `fuzzing_worker` (stages 3-4)
- HTTP method testing from `webapp_worker`

This worker runs against each individual host/URL — not just the root domain. After `TargetExpander` creates child targets, each child runs its own config_mgmt pipeline.

---

## Pipeline Stages

### Stage 1: network_infrastructure (Section 4.2.1)

**Objective:** Validate that the server's network configuration is properly segmented, no unnecessary ports are open, and infrastructure components are not exposing management interfaces.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| Nmap | Carried (recon_core/network_worker) | HEAVY | Deep service scan (`-sV -sC`) on all ports discovered by info_gathering stage 9. NSE scripts for service-specific enumeration (http-enum, ssl-enum-ciphers, smb-os-discovery). Identifies unnecessary services (FTP, Telnet, SNMP) that should be firewalled. Flags management ports (SSH on non-standard, RDP, VNC) exposed to public. |
| NetworkConfigAuditor | New | LIGHT | Analyzes Nmap results and performs follow-up checks: DNS zone transfer attempts (AXFR), reverse DNS enumeration for IP neighbors, traceroute analysis for network segmentation, SNMP community string testing (public/private defaults). Checks if development ports (3000, 5000, 8080, 8443, 9200) are exposed in production. Stores findings as Observation records. |

**Outputs:** Observation records (open ports, service versions, segmentation issues).

---

### Stage 2: platform_configuration (Section 4.2.2)

**Objective:** Validate that the web server and application server are hardened — no default configurations, debug modes, or unnecessary features enabled.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| PlatformAuditor | New | LIGHT | Platform-specific configuration checks based on framework fingerprint from info_gathering stage 8. **Apache:** check for `ServerSignature On`, `ServerTokens Full`, exposed `/server-status`, `/server-info`. **Nginx:** check for `autoindex on`, exposed `/nginx_status`. **IIS:** check for exposed `/trace.axd`, WebDAV enabled. **Tomcat:** check for `/manager/html`, `/host-manager`. **PHP:** check for `phpinfo()` pages, `display_errors=On`. **Django:** check for `DEBUG=True` (detailed error pages with settings dump). **Node.js/Express:** check for stack traces in error responses, exposed `/debug`. **WordPress:** check for `wp-config.php.bak`, exposed `wp-json/wp/v2/users`. Stores each misconfiguration as a Vulnerability record with remediation guidance. |

**Outputs:** Vulnerability records (misconfigurations), Observation records (platform details).

---

### Stage 3: file_extension_handling (Section 4.2.3)

**Objective:** Test whether the server serves sensitive file types as plaintext instead of processing them or blocking access.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| ExtensionProber | New | LIGHT | For each discovered web root, requests files with sensitive extensions to test handling: `.inc`, `.config`, `.conf`, `.cfg`, `.ini`, `.log`, `.sql`, `.bak`, `.old`, `.orig`, `.tmp`, `.swp`, `.swo`, `~` (vim backup), `.env`, `.DS_Store`, `.htaccess`, `.htpasswd`, `.git/config`, `.svn/entries`. Checks response: if status 200 and content-type is `text/plain` or `application/octet-stream`, the file is being served raw. If status 403/404, the server is properly blocking. Response body is scanned for credential patterns (passwords, API keys, database connection strings). Each exposed file stored as a Vulnerability record. |

**Outputs:** Vulnerability records (exposed sensitive files).

---

### Stage 4: backup_unreferenced_files (Section 4.2.4)

**Objective:** Discover old, backup, and unreferenced files that may contain source code, credentials, or configuration data.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| FfufTool | Carried (fuzzing_worker) | HEAVY | Directory and file brute-forcing with backup-focused wordlists. Wordlist selection based on target's `rate_limit` config (large wordlist if rate_limit ≥ 50 req/s, small if < 50). Filters by response code (200, 204, 301, 302, 401, 403) with auto-calibrated soft-404 baseline. Targets: common backup patterns (`index.php.bak`, `config.old`, `database.sql.gz`), version control artifacts (`.git/`, `.svn/`, `.hg/`), IDE files (`.idea/`, `.vscode/`), deployment artifacts (`deploy.sh`, `Makefile`, `docker-compose.yml`). |
| BackupScanner | New | LIGHT | Generates backup filename permutations from known files. For each discovered file (e.g., `config.php`), tests: `config.php.bak`, `config.php.old`, `config.php.orig`, `config.php.save`, `config.php~`, `config.php.swp`, `.config.php.swp`, `config.php.1`, `config_backup.php`, `config.php.dist`, `config.php.sample`. Also checks common database dump locations: `/backup/`, `/backups/`, `/dump/`, `/export/`, `/db/`. Complements FfufTool by targeting known-file variants rather than brute-forcing blindly. |

**Outputs:** Location records (discovered files), Vulnerability records (exposed backups with sensitive content).

---

### Stage 5: admin_interface_enumeration (Section 4.2.5)

**Objective:** Discover administrative interfaces and management consoles, check for default credentials on them.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| AdminFinder | New | LIGHT | Brute-forces common admin paths: `/admin`, `/administrator`, `/admin.php`, `/wp-admin`, `/cpanel`, `/phpmyadmin`, `/adminer`, `/manager`, `/console`, `/dashboard`, `/portal`, `/cms`, `/backend`, `/control`, `/webadmin`, `/sysadmin`, `/maintenance`, `/setup`, `/install`. Path list is augmented based on framework fingerprint (WordPress → `/wp-admin`, Django → `/admin`, Laravel → `/nova`, Rails → `/rails/info`). Checks response codes and page titles to confirm admin interfaces vs generic 404s. |
| DefaultCredChecker | New | LIGHT | For each discovered admin interface, tests common default credential pairs: `admin/admin`, `admin/password`, `admin/123456`, `root/root`, `root/toor`, `administrator/administrator`, `test/test`, `guest/guest`. Also tests vendor-specific defaults based on platform fingerprint (Tomcat `tomcat/s3cret`, Jenkins `admin/admin`, Grafana `admin/admin`). Rate-limited to 1 attempt per 3 seconds to avoid lockouts. Successful logins recorded as CRITICAL Vulnerability records. |

**Outputs:** Location records (admin interfaces), Vulnerability records (accessible admin panels, default credentials).

---

### Stage 6: http_methods (Section 4.2.6)

**Objective:** Identify dangerous HTTP methods enabled on the server that could allow unauthorized file modification or information disclosure.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| MethodTester | New | LIGHT | For each discovered endpoint (sample of top 20 by uniqueness), sends an OPTIONS request and parses the `Allow` header. Then sends actual requests with each dangerous method: **PUT** — attempts file upload to test directory (non-destructive test file). **DELETE** — sends DELETE to a non-existent resource, checks if method is accepted. **TRACE** — sends TRACE request, checks if response echoes the request body (XST vulnerability — can steal cookies via JavaScript). **CONNECT** — tests for proxy abuse. **PATCH** — tests for unprotected partial updates. Results compared against expected behavior (most endpoints should only allow GET, POST, HEAD). Each dangerous method that succeeds stored as a Vulnerability record with severity based on method type (PUT/DELETE → HIGH, TRACE → MEDIUM). |

**Outputs:** Vulnerability records (dangerous methods enabled), Observation records (method inventory per endpoint).

---

### Stage 7: hsts_testing (Section 4.2.7)

**Objective:** Verify that the application enforces encrypted connections via HTTP Strict Transport Security.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| HstsAuditor | New | LIGHT | Checks HSTS implementation across all discovered hosts: **Header presence** — `Strict-Transport-Security` header on HTTPS responses. **max-age** — minimum 31536000 (1 year) recommended, flag if < 2592000 (30 days). **includeSubDomains** — flag if missing when subdomains serve sensitive content. **preload** — check if domain is in the HSTS preload list (hstspreload.org API). **HTTP redirect** — verify that HTTP (port 80) redirects to HTTPS with 301 (not 302 — must be permanent). **Mixed content** — check if HTTPS pages load resources over HTTP. Each issue stored as a Vulnerability record (missing HSTS → MEDIUM, short max-age → LOW, no preload → INFO). |

**Outputs:** Vulnerability records (HSTS issues), Observation records (HSTS configuration details).

---

### Stage 8: cross_domain_policy (Section 4.2.8)

**Objective:** Verify that cross-domain policy files do not grant overly permissive access to external domains.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CrossDomainPolicyParser | New | LIGHT | Fetches and analyzes: **crossdomain.xml** (Flash/Flex) — flags `<allow-access-from domain="*"/>` as CRITICAL, any wildcard subdomain pattern as HIGH. **clientaccesspolicy.xml** (Silverlight) — same analysis. **CORS headers** — preliminary CORS check (detailed CORS testing in client_side worker stage 7, but basic misconfiguration flagged here). Checks for `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` (browser ignores wildcard with credentials, but misconfiguration indicates poor understanding). Each overly permissive policy stored as a Vulnerability record. |

**Outputs:** Vulnerability records (permissive cross-domain policies).

---

### Stage 9: file_permissions (Section 4.2.9)

**Objective:** Test whether sensitive configuration files or directories are world-readable or writable from the web.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| PermissionProber | New | LIGHT | Tests access to files that should never be web-accessible: **Configuration files** — `.htaccess`, `web.config`, `nginx.conf`, `apache2.conf` (if served). **Environment files** — `.env`, `.env.production`, `.env.local`. **Private keys** — `*.pem`, `*.key`, `id_rsa`. **Database files** — `*.sqlite`, `*.db`. **Source code** — `*.py`, `*.rb`, `*.php` in non-standard locations. **Upload directories** — checks if upload directories allow listing (`GET /uploads/` returns directory index). **Write testing** — attempts PUT to upload directories to check if write access is enabled (uploads a test `.txt` file, immediately deletes if successful). Each accessible sensitive file stored as a Vulnerability record. |

**Outputs:** Vulnerability records (exposed sensitive files, writable directories).

---

### Stage 10: subdomain_takeover (Section 4.2.10)

**Objective:** Identify subdomains with dangling DNS records that point to decommissioned external services, allowing an attacker to claim them.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SubjackTool | Carried (recon_core) | LIGHT | Checks all discovered subdomains for takeover potential. Tests against known vulnerable services: GitHub Pages (404 response with "There isn't a GitHub Pages site here"), Heroku ("No such app"), AWS S3 ("NoSuchBucket"), Azure ("404 Web Site not found"), Shopify, Fastly, Pantheon, Tumblr, WordPress.com, Ghost, Surge.sh, Bitbucket, and 30+ others. Each takeover candidate stored as a CRITICAL Vulnerability record — subdomain takeover enables phishing, cookie theft, and authentication bypass. |
| CnameChecker | New | LIGHT | Resolves CNAME records for all subdomains and checks if the CNAME target is claimable. Catches cases SubjackTool misses — e.g., CNAME → custom domain on a provider that returned 200 but with default/unclaimed content. Cross-references CNAME targets against known cloud provider patterns (*.s3.amazonaws.com, *.azurewebsites.net, *.herokuapp.com). Also checks for dangling MX records (email takeover) and dangling NS records (full DNS takeover — CRITICAL). |

**Outputs:** Vulnerability records (takeover candidates with severity and PoC steps).

---

### Stage 11: cloud_storage (Section 4.2.11)

**Objective:** Discover and test cloud storage resources (S3 buckets, Azure Blobs, GCP buckets) for misconfigurations.

This stage absorbs the entire `cloud_worker`.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| BucketFinder | New | LIGHT | Generates potential bucket names from the target domain using common patterns: `{domain}`, `{domain}-backup`, `{domain}-assets`, `{domain}-uploads`, `{domain}-static`, `{domain}-dev`, `{domain}-staging`, `{domain}-prod`, `{domain}-logs`, `{domain}-data`. Tests existence on AWS S3, Azure Blob Storage, and GCP Cloud Storage simultaneously. |
| S3Scanner | Carried (cloud_worker) | LIGHT | For each discovered S3 bucket: tests public read (`GET`), public write (`PUT` test object — immediately deleted), ACL listing (`GET ?acl`), bucket policy retrieval. Scans accessible bucket contents for sensitive files (`.env`, credentials, database dumps, PII). Each misconfiguration stored as a Vulnerability record with severity (public write → CRITICAL, public read with sensitive data → HIGH, public listing → MEDIUM). |
| AzureBlobProber | New | LIGHT | Azure Blob Storage equivalent of S3Scanner. Tests container listing (`GET ?restype=container&comp=list`), blob access, SAS token exposure, and anonymous access level (container vs blob vs private). |
| GcpBucketProber | New | LIGHT | GCP Cloud Storage equivalent. Tests `storage.googleapis.com/{bucket}` endpoints, checks IAM permissions for `allUsers` and `allAuthenticatedUsers`, tests uniform vs fine-grained access control. |
| TrufflehogTool | Carried (cloud_worker/api_worker) | HEAVY | Scans accessible cloud storage contents for secrets — API keys, AWS credentials, database passwords, OAuth tokens, private keys. Uses entropy analysis + regex patterns + verified checks (attempts to authenticate with discovered credentials against the respective service API). Each confirmed secret stored as a CRITICAL Vulnerability record. |

**Outputs:** Vulnerability records (bucket misconfigurations, exposed secrets), CloudAsset records.

---

## Concurrency Configuration

```python
# workers/config_mgmt/concurrency.py

HEAVY_LIMIT = 2
LIGHT_LIMIT = cpu_count()

TOOL_WEIGHTS = {
    "Nmap": "HEAVY",
    "NetworkConfigAuditor": "LIGHT",
    "PlatformAuditor": "LIGHT",
    "ExtensionProber": "LIGHT",
    "FfufTool": "HEAVY",
    "BackupScanner": "LIGHT",
    "AdminFinder": "LIGHT",
    "DefaultCredChecker": "LIGHT",
    "MethodTester": "LIGHT",
    "HstsAuditor": "LIGHT",
    "CrossDomainPolicyParser": "LIGHT",
    "PermissionProber": "LIGHT",
    "SubjackTool": "LIGHT",
    "CnameChecker": "LIGHT",
    "BucketFinder": "LIGHT",
    "S3Scanner": "LIGHT",
    "AzureBlobProber": "LIGHT",
    "GcpBucketProber": "LIGHT",
    "TrufflehogTool": "HEAVY",
}
```

---

## Base Tool Class

```python
# workers/config_mgmt/base_tool.py

class ConfigMgmtTool(ABC):
    """Abstract base for all config_mgmt tools.

    Adds config-specific helpers:
    - check_response_for_info_leak() — scan response bodies for sensitive patterns
    - test_url_access() — check if a URL returns content vs 403/404
    - compare_responses() — diff two responses to detect subtle differences
    """
    worker_type = "config_mgmt"
```

---

## Interaction with Traffic Proxy

This worker generally does **not** use the traffic proxy. All testing is direct HTTP requests against the target. The proxy is not needed because config_mgmt stages don't manipulate request parameters or need request interception — they inspect server responses to standard requests.

Exception: Stage 6 (http_methods) may optionally route through the proxy to capture full request/response for PoC documentation of dangerous method acceptance.

---

## Interaction with Callback Server

Stage 11 (cloud_storage) uses the callback server for TrufflehogTool — when discovered credentials are tested for validity, the callback server can receive confirmation pings from verified service connections.
