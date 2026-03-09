# Vulnerability Scanning Worker

Act as a Senior Security Engineer specializing in Automated Vulnerability Assessment.
Task: Create the "Vuln-Scanner" Dockerized worker. This container uses template-based scanning and active exploitation tools to identify and confirm security flaws across the discovered attack surface.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Go 1.21+, Python 3.10+, Ruby, JRE 11+, PHP CLI.
- **Template Scanner**: **Nuclei** (ProjectDiscovery).
- **Templates**:
    - Automated daily sync of **Nuclei-Templates**.
    - Integration for **Cent** (to manage community-contributed templates).
    - Custom Template Folder: `/app/shared/custom_templates/` for proprietary logic.
- **Active Injection Tools**:
    - **sqlmap**: Adaptive SQL injection with WAF bypass, tamper scripts, DB fingerprinting.
    - **tplmap**: Server-side template injection across Jinja2, Twig, Freemarker, Mako, Pebble, Velocity, Smarty.
    - **XXEinjector**: XML external entity injection with OOB exfiltration via interactsh.
    - **commix**: OS command injection via GET/POST/headers/cookies (classic, time-based, file-based).
    - **SSRFmap**: SSRF testing against URL/redirect params for internal network and cloud metadata access.
    - **smuggler**: HTTP request smuggling detection (CL.TE, TE.CL, TE.TE).
    - **Host Header Tool** (custom Python): Password reset poisoning, cache poisoning, routing-based SSRF.
    - **ysoserial**: Java deserialization gadget chain payloads (CommonsCollections, Spring, Hibernate).
    - **phpggc**: PHP deserialization gadget chain payloads per framework version.

## 2. Scanning Logic & Input Ingestion

- **Target Ingestion**:
    - Query the `locations` table for live web services (port 80/443, state='open').
    - Query the `assets` table (type='url') for paths found during fuzzing.
    - Query the `cloud_assets` table for buckets to check for misconfigurations.
    - Query the `parameters` table for all discovered GET/POST parameters (from Phase 6 Arjun output).
- **Context-Aware Scanning**:
    - If `observations.tech_stack` shows "Apache", trigger Apache-specific templates.
    - If `observations.tech_stack` shows "WordPress", trigger WP-plugin and core templates.
    - If `observations.tech_stack` shows Java/Spring/Tomcat, enable ysoserial.
    - If `observations.tech_stack` shows PHP/Laravel/Symfony, enable phpggc.
    - If `observations.tech_stack` shows a template engine, enable tplmap with engine hint.
- **Header Injection**: Must pass `custom_headers` to Nuclei via the `-H` flag and to all active tools for authenticated scanning.

## 3. Execution Strategy (3-Stage Pipeline)

Implement a Python controller that orchestrates three sequential stages:

### Stage 1: `nuclei_sweep`
- Run a full Nuclei template scan across all live assets.
- Filter templates based on "Tech Stack" fingerprints from the `observations` table.
- **Exclusion Logic**: Automatically skip templates that match the `oos_attacks` list (e.g., "No DoS", "No Brute Force").
- Write all findings to `vulnerabilities` with `source_tool="nuclei:<template-id>"`.

### Stage 2: `active_injection` (Nuclei-Triaged)
- Query `vulnerabilities` from Stage 1 where `source_tool LIKE 'nuclei:%'`.
- Route findings to the matching active tool for deep confirmation:
    - SQLi finding → **sqlmap** (`--risk`/`--level` based on severity, `--tamper` for WAF bypass, `--batch`).
    - SSTI finding → **tplmap** (engine auto-detected from `tech_stack`).
    - XXE finding → **XXEinjector** (OOB via interactsh callback).
    - CMDi/RCE finding → **commix** (`--technique` auto-selected).
    - SSRF finding → **SSRFmap** (internal IPs + cloud metadata endpoints).
- Confirmed vulns update the existing record: severity escalated, PoC replaced with full exploit proof.

### Stage 3: `broad_injection_sweep`
- Run active tools against ALL injectable surfaces, not just Nuclei-flagged targets.
- Skip any target+parameter combos already confirmed in Stage 2.
- Tools run in parallel:
    - **sqlmap** → all URLs with parameters from `parameters` table.
    - **tplmap** → URLs with parameters where `tech_stack` suggests template engine.
    - **commix** → all URLs with parameters.
    - **SSRFmap** → URLs where `param_name` matches url/redirect/proxy/callback/next/return/dest/uri/path.
    - **smuggler** → all live HTTP locations (raw socket, no parameter dependency).
    - **Host Header Tool** → all live locations + Phase 6 vhosts (reset poisoning, cache poisoning, routing SSRF).
    - **ysoserial** → URLs where `tech_stack` shows Java/Spring/Tomcat.
    - **phpggc** → URLs where `tech_stack` shows PHP/Laravel/Symfony.

## 4. Database & Event Reporting

- **Vulnerability Sync**: Every finding must be written to the `vulnerabilities` table with:
    - Severity (Critical, High, Medium, Low, Info).
    - Template-ID and Type (in `source_tool`).
    - **Proof of Concept (PoC)**: The matched request/response pair.
- **Alerting**: Immediate insertion into the `alerts` table for any finding with Severity >= High.
- **Mapping**: Link the vulnerability to the specific `asset_id` in the DB.
- **Deduplication**: Before running any active tool, check `vulnerabilities` for existing confirmed finding on the same target+parameter. Skip if already confirmed.

## 5. Resource & Performance

- **Rate Limiting**: Adhere to the `rate_limit` (PPS/Requests per second). Passed to each tool: sqlmap (`--delay`), commix (`--delay`), tplmap (`--delay`).
- **Persistence**: Use the 24-hour rule to avoid re-scanning the same asset/tool combination unless a "Force Scan" is triggered.

Deliverables: Dockerfile, Nuclei wrapper script, Template update automation, active injection tool wrappers (sqlmap, tplmap, XXEinjector, commix, SSRFmap, smuggler, host header tool, ysoserial, phpggc), and SQL mapping logic.
