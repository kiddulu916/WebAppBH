# WSTG-Aligned Restructure — 06 Input Validation Worker

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview, restructure-01-infrastructure-services
**WSTG Section:** 4.7 Input Validation Testing
**Worker Directory:** `workers/input_validation/`
**Queue:** `input_validation_queue`
**Trigger:** info_gathering complete (parallel with config_mgmt and client_side)

---

## Overview

The largest worker in the framework — 15 pipeline stages covering all injection and input manipulation attacks. Absorbs tools from:
- `vuln_scanner` (sqlmap, tplmap, xxeinjector, commix, ssrfmap, smuggler, host_header)
- `fuzzing_worker` (crlfuzz)
- `webapp_worker` (dalfox)
- `api_worker` (nosqlmap)
- `network_worker` (LDAP injection)

This worker runs against all entry points discovered by info_gathering stage 6. The more parameters and input vectors discovered, the more thorough the testing.

### Entry Point Injection Strategy

Every stage receives the full list of Parameter records from info_gathering. Each tool iterates over relevant parameters based on their `param_type`:
- **query** — URL query parameters
- **body** — POST body parameters (form-encoded or JSON)
- **header** — HTTP request headers (Cookie, Referer, User-Agent, custom headers)
- **file** — File upload fields
- **hidden** — Hidden form fields

Not every parameter is relevant to every injection type. Tools filter based on context:
- SQLi tools target parameters that interact with databases (search, filter, sort, ID parameters)
- XSS tools target parameters that reflect in HTML responses
- Command injection tools target parameters that may reach system calls (filename, path, command parameters)

---

## Pipeline Stages

### Stage 1: reflected_xss (Section 4.7.1)

**Objective:** Identify parameters that reflect user input in the response without proper sanitization, enabling script execution in the victim's browser.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| DalfoxTool | Carried (webapp_worker) | HEAVY | Automated reflected XSS scanner. Runs against all discovered URLs with parameters. Features: DOM-based analysis, WAF bypass payloads, blind XSS via callback server (registers callback URL, injects payload pointing to it), parameter mining from page source. Configured with `--blind CALLBACK_URL` for blind XSS, `--custom-payload` for framework-specific payloads, `--waf-evasion` when WAF detected by info_gathering. |
| XssProber | New | LIGHT | Custom XSS scanner for injection points Dalfox cannot reach: (1) **JSON API parameters** — inject payloads into JSON values, check if response reflects unsanitized. (2) **WebSocket messages** — inject XSS payloads into WS message fields. (3) **Multipart form data** — inject into file name fields and other multipart boundaries. (4) **HTTP headers** — inject into User-Agent, Referer, X-Forwarded-For — check if reflected in error pages or admin panels (stored XSS via logs goes to stage 2). (5) **XML/SOAP parameters** — inject into XML element values. Uses BrowserManager for payload execution verification. |

**Callback server usage:** DalfoxTool registers blind XSS callbacks. If a stored/delayed XSS fires hours later (e.g., admin views a log entry containing the payload), the callback server catches it.

---

### Stage 2: stored_xss (Section 4.7.2)

**Objective:** Identify stored XSS — payloads persisted in the database and rendered to other users.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| StoredXssScanner | New | HEAVY | Multi-step testing process: (1) **Identify persistent input fields** — comment forms, profile fields (display name, bio, website), messaging systems, review/feedback forms, file upload descriptions, support tickets. (2) **Inject payloads** — using Tester session, write XSS payloads into each persistent field. Payloads include various event handler and script tag variants, polyglot payloads for multi-context escaping. (3) **Check rendering** — navigate to pages where the content is displayed (profile page, comment section, admin panel). Use BrowserManager to detect if payloads execute. (4) **Cross-user check** — check if the payload would render for the Testing User's view (by accessing the shared page as Tester). (5) **Cleanup** — edit/delete injected content where possible. Requires BrowserManager for JavaScript execution detection. Each confirmed stored XSS is a HIGH-CRITICAL Vulnerability with full injection-to-rendering chain as PoC. |

**Incubated vulnerabilities (WSTG 4.7.14)** are tested here — payloads that only execute after a delay (batch processing, email rendering, PDF generation).

---

### Stage 3: http_verb_tampering (Section 4.7.3)

**Objective:** Test if security filters can be bypassed by using unexpected HTTP methods.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| VerbTamperTester | New | LIGHT | For each protected endpoint (that returns 403 with the standard method): (1) Replay with alternative methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT. (2) Test method override headers: `X-HTTP-Method-Override`, `X-Method-Override`, `_method` in POST body. (3) Compare responses — if a blocked GET returns 200 when sent as HEAD or PUT, verb tampering bypass is confirmed. (4) Test arbitrary methods: `JEFF`, `TEST`, `FOO` — some WAFs/frameworks fall through to default allow for unknown methods. Each bypass is a MEDIUM-HIGH Vulnerability. |

---

### Stage 4: http_parameter_pollution (Section 4.7.4)

**Objective:** Test if duplicate parameters confuse application logic or bypass security filters.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| HppTester | New | LIGHT | For each discovered parameter: (1) **Duplicate parameters** — `?id=1&id=2`. Different servers handle this differently: Apache/PHP uses last, ASP.NET uses first, Java concatenates. (2) **Split parameters** — parameter in both query string and POST body. Test which value the application uses. (3) **WAF bypass** — if a WAF blocks a payload, test splitting the payload across duplicate parameters (concatenation bypass). (4) **Logic manipulation** — duplicate price, admin, or role parameters to test which value wins. (5) **Array notation** — `?id[]=1&id[]=2`, `?id=1,2`, `?id=1;2` — test how the application handles array-like parameters. Each confirmed HPP is a MEDIUM Vulnerability. WAF bypass via HPP is HIGH. |

---

### Stage 5: sql_injection (Section 4.7.5)

**Objective:** Test all injectable parameters for SQL injection across all database types.

**Sub-tools run concurrently.** Database type is inferred from framework fingerprint (info_gathering stage 8). If unknown, all variants run.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SqlmapOracle | Config wrapper | HEAVY | sqlmap with `--dbms=Oracle`, Oracle-specific tamper scripts. Tests UTL_HTTP for OOB data exfiltration via callback server. |
| SqlmapMysql | Config wrapper | HEAVY | sqlmap with `--dbms=MySQL`, MySQL tamper scripts. Tests INFORMATION_SCHEMA access, INTO OUTFILE for file write. |
| SqlmapMssql | Config wrapper | HEAVY | sqlmap with `--dbms=MSSQL`, MSSQL tamper scripts. Tests xp_cmdshell for command execution, error-based extraction. |
| SqlmapPostgres | Config wrapper | HEAVY | sqlmap with `--dbms=PostgreSQL`, PostgreSQL tamper scripts. Tests pg_sleep for time-based, COPY command for file read. |
| SqlmapAccess | Config wrapper | HEAVY | sqlmap with `--dbms=Access`. Limited attack surface but tested for completeness. |
| NosqlmapTool | Carried (api_worker) | LIGHT | NoSQL injection testing for MongoDB, CouchDB, Redis. Tests operator injection in JSON parameters, `$where` clause injection, map-reduce function injection. Targets JSON API endpoints specifically. |
| OrmInjectionTester | New | LIGHT | Tests ORM-specific bypasses that sqlmap may miss: SQLAlchemy filter bypass, Hibernate/JPA HQL injection, ActiveRecord where clause injection, Sequelize operator injection. Selected based on framework fingerprint. |
| ClientSideSqlTester | New | LIGHT | Tests client-side SQL databases: WebSQL (deprecated but present in some Chromium apps), SQLite in hybrid apps, IndexedDB queries using unsanitized input. Requires BrowserManager for client-side database interaction. |

**Concurrency:** Only 2 HEAVY sqlmap instances run at a time. LIGHT tools run concurrently with the HEAVY tools.

**Callback server usage:** OOB SQLi data exfiltration (Oracle UTL_HTTP, MSSQL xp_dirtree) uses callback URLs for confirmation.

Each confirmed SQLi is a CRITICAL Vulnerability with PoC (injection point, payload, extracted data sample).

---

### Stage 6: ldap_injection (Section 4.7.6)

**Objective:** Test for LDAP filter injection in applications that use directory services for authentication or user lookup.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| LdapInjectionTester | Carried (network_worker) | LIGHT | Tests parameters that may interact with LDAP: login forms, user search, directory lookups. (1) **Filter manipulation** — inject LDAP filter operators into search parameters. (2) **Authentication bypass** — inject into username field to bypass LDAP bind authentication. (3) **Blind LDAP** — timing-based detection via wildcard complexity — response time difference indicates LDAP processing. (4) **Data extraction** — if injection confirmed, enumerate attributes via boolean-based blind techniques. Only runs if LDAP-related technology is detected in framework fingerprint or login flow analysis. |

---

### Stage 7: xml_injection (Section 4.7.7)

**Objective:** Test for XML External Entity (XXE) injection in XML-accepting endpoints.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| XxeInjectorTool | Carried (vuln_scanner) | HEAVY | Comprehensive XXE testing: (1) **Classic XXE** — external entity declaration in XML body. (2) **Parameter entity XXE** — for OOB extraction via callback server. (3) **Blind XXE** — no response reflection, use callback server for confirmation. (4) **XXE via file upload** — DOCX, XLSX, SVG files containing XXE payloads. (5) **XXE via Content-Type** — change JSON Content-Type to XML and send XML body with XXE. (6) **SSRF via XXE** — entity pointing to cloud metadata endpoints for internal access. Uses callback server for all blind XXE variants. Each confirmed XXE is a HIGH-CRITICAL Vulnerability. |

---

### Stage 8: ssi_injection (Section 4.7.8)

**Objective:** Test for Server-Side Includes injection in applications that process SSI directives.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SsiTester | New | LIGHT | Injects SSI directives into all text input fields: command execution directives, file inclusion directives, environment variable echo directives, and configuration directives (least harmful, good for detection). Detection: response contains command output, file contents, or injected configuration string. Only relevant for Apache with mod_include or Nginx with ssi on — check framework fingerprint before running. Each confirmed SSI is a HIGH Vulnerability. |

---

### Stage 9: xpath_injection (Section 4.7.9)

**Objective:** Test for XPath injection in XML-backed data queries.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| XpathTester | New | LIGHT | Targets parameters that may query XML data stores: (1) **Boolean-based** — inject true/false conditions, compare responses. Different results confirm injection. (2) **Error-based** — inject malformed XPath and check for XPath error messages in response. (3) **Union-based** — inject union expressions to extract additional data. (4) **Blind timing** — inject complex XPath expressions and measure response time differences. Particularly relevant for applications using XML configuration files, XSLT transformations, or XML databases. |

---

### Stage 10: imap_smtp_injection (Section 4.7.10)

**Objective:** Test for email header injection in forms that send emails.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| MailInjectionTester | New | LIGHT | Identifies forms that trigger email sending: contact forms, feedback forms, invite-friend features. (1) **Header injection** — inject CRLF + CC/BCC headers into name/subject/email fields. (2) **Subject injection** — inject CRLF + new Subject + new Body to overwrite email content. (3) **SMTP command injection** — inject SMTP protocol commands for mail relay manipulation. Detection: use callback server email address as injection target — if email arrives at callback, injection confirmed. Each confirmed injection is a MEDIUM-HIGH Vulnerability. |

---

### Stage 11: code_injection (Section 4.7.11)

**Objective:** Test for local and remote file inclusion, and general code injection.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| LfiTester | New | LIGHT | Local File Inclusion testing: (1) **Basic LFI** — directory traversal sequences to read system files. (2) **Null byte** — truncation for older runtimes. (3) **PHP wrappers** — php://filter for source code disclosure, php://input for POST body as code, data:// protocol for inline code. (4) **Log poisoning** — inject code into User-Agent, then include the log file. (5) **Path truncation** — long path to exceed OS path limit and truncate extension. Tests against all file-related parameters discovered by info_gathering. |
| RfiTester | New | LIGHT | Remote File Inclusion testing: (1) Register callback URL. (2) Inject callback URL into file parameters. (3) If callback receives a request, server attempted to fetch the remote file (RFI confirmed). (4) Test with different protocols: http, https, ftp, data. (5) Test URL encoding to bypass filters. Each confirmed RFI is a CRITICAL Vulnerability. |
| CommixTool | Carried (vuln_scanner) | HEAVY | General code injection via code interpretation functions: PHP, Python, Ruby, Node.js code injection payloads. Selected based on framework fingerprint. |

**Callback server usage:** RfiTester uses callback URLs for remote inclusion confirmation. CommixTool uses callback for blind code execution confirmation.

---

### Stage 12: command_injection (Section 4.7.12)

**Objective:** Test for OS command injection via parameters that reach system-level interpreters.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CommandInjectionTester | New | LIGHT | Supplements CommixTool with OS-specific payloads: **Linux:** backticks, `$()`, semicolons, pipes, logical operators, newlines. **Windows:** `&`, pipes, logical operators, PowerShell syntax. (1) Targets parameters likely to reach system calls: filename, path, hostname, IP address, URL, command parameters. (2) **Blind detection** — use callback server for HTTP/DNS callback confirmation. (3) **Time-based** — sleep/ping commands with measurable response time delta. (4) **Filter bypass** — IFS variable, quote splitting, hex encoding. |

---

### Stage 13: format_string (Section 4.7.13)

**Objective:** Test for format string vulnerabilities in applications using C/Python/Perl backends.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| FormatStringTester | New | LIGHT | Inject format specifiers into all parameters: (1) **Memory disclosure** — hex dump specifiers, string pointer dereference, pointer value specifiers. (2) **Crash detection** — write-to-memory specifiers (send only with explicit user approval for non-production targets). (3) **Detection** — compare response for injected specifiers vs literal text. If response contains hex values, format string is confirmed. (4) **Python-specific** — Python format string injection via class traversal for code execution. Only relevant for C, Python, or Perl backends. Skip for Java, Node.js, PHP, Ruby. Each confirmed format string is a HIGH-CRITICAL Vulnerability. |

---

### Stage 14: http_splitting_smuggling (Section 4.7.15, 4.7.16, 4.7.17)

**Objective:** Test for HTTP request smuggling, response splitting, and host header injection.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SmugglerTool | Carried (vuln_scanner) | HEAVY | HTTP request smuggling via front-end/back-end desync: (1) **CL.TE** — front-end uses Content-Length, back-end uses Transfer-Encoding. (2) **TE.CL** — front-end uses Transfer-Encoding, back-end uses Content-Length. (3) **TE.TE** — both use Transfer-Encoding but with obfuscation variants. (4) **H2.CL / H2.TE** — HTTP/2 downgrade smuggling. Detection via callback server — smuggled request contains callback URL. Each confirmed smuggling is a CRITICAL Vulnerability. |
| HostHeaderTool | Carried (vuln_scanner) | LIGHT | Host header manipulation: (1) **Password reset poisoning** — trigger reset with manipulated Host, check if reset link contains attacker domain. (2) **Cache poisoning** — inject Host on cacheable page, check if cached response serves attacker content to other users. (3) **Routing-based SSRF** — Host pointing to cloud metadata through reverse proxy misconfiguration. (4) **Web cache deception** — cache authenticated page as static asset. Uses traffic proxy opt-in for precise header manipulation. |
| CrlfuzzTool | Carried (fuzzing_worker) | LIGHT | CRLF injection / HTTP response splitting: (1) Inject CRLF into parameters and check if it appears in response headers. (2) **Response splitting** — inject arbitrary response body via CRLF. (3) **Header injection** — inject Set-Cookie headers via CRLF. (4) **Log injection** — CRLF in log-destined parameters to forge log entries. |

**WSTG 4.7.16 (HTTP Incoming Requests)** is covered by SmugglerTool's desync detection.

---

### Stage 15: ssrf_ssti (Section 4.7.18, 4.7.19)

**Objective:** Test for Server-Side Request Forgery and Server-Side Template Injection.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| SsrfmapTool | Carried (vuln_scanner) | HEAVY | SSRF testing: (1) **Cloud metadata** — AWS, GCP, Azure metadata endpoint probing. (2) **Internal service probing** — localhost on common internal service ports (Redis, Elasticsearch, Memcached). (3) **Protocol smuggling** — gopher, dict, file protocol abuse via SSRF. (4) **DNS rebinding** — domain that resolves to internal IP on second lookup. (5) **Filter bypass** — decimal IP, IPv6, URL encoding, alternate representations. Uses callback server for blind SSRF confirmation. Each confirmed SSRF is a HIGH-CRITICAL Vulnerability. |
| TplmapTool | Carried (vuln_scanner) | HEAVY | Server-side template injection: (1) **Detection** — inject math expressions in various template syntaxes and check for computed results in response. (2) **Engine identification** — use engine-specific payloads to determine template engine. (3) **Exploitation** — engine-specific code execution payloads for Jinja2, Twig, Freemarker, Velocity, ERB. (4) **Blind SSTI** — use callback server for time-based or OOB confirmation. Selected based on framework fingerprint. Each confirmed SSTI is a CRITICAL Vulnerability (RCE). |

---

## Concurrency Configuration

```python
# workers/input_validation/concurrency.py

HEAVY_LIMIT = 2    # Only 2 heavy tools at a time (sqlmap instances, smuggler, etc.)
LIGHT_LIMIT = cpu_count()

# Note: sqlmap variants are mutually exclusive within stage 5 —
# only the relevant DB-type variants run (based on fingerprint).
# If DB type unknown, they rotate through the HEAVY semaphore.
```

---

## Traffic Proxy Usage

Stages that use the traffic proxy (opt-in):
- Stage 4 (HPP) — split parameters across query/body
- Stage 5 (SQLi) — inject into specific request positions
- Stage 14 (smuggling/splitting) — precise header manipulation for CL.TE/TE.CL desync

---

## Callback Server Usage

Stages that use the callback server:
- Stage 1 (reflected XSS) — blind XSS detection
- Stage 2 (stored XSS) — delayed execution detection
- Stage 5 (SQLi) — OOB data exfiltration
- Stage 7 (XXE) — blind XXE confirmation
- Stage 10 (mail injection) — email delivery confirmation
- Stage 11 (code injection) — RFI confirmation, blind code execution
- Stage 12 (command injection) — blind command execution
- Stage 14 (smuggling) — smuggled request confirmation
- Stage 15 (SSRF/SSTI) — blind SSRF and SSTI confirmation
