# WSTG-Aligned Restructure — 07 Error Handling, Cryptography, Business Logic & Client-Side Workers

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview, restructure-05-identity-auth-authz-session
**WSTG Sections:** 4.8, 4.9, 4.10, 4.11

---

This document covers four workers that run after the identity/auth/authz/session chain completes. Error handling and cryptography run in parallel (no mutual dependency). Business logic depends on both. Client-side runs in parallel with business logic.

---

# Part A: Error Handling Worker (Section 4.8)

**Worker Directory:** `workers/error_handling/`
**Queue:** `error_handling_queue`
**Trigger:** config_mgmt complete
**WSTG Section:** 4.8 Error Handling

---

## Overview

The error_handling worker tests how the application responds to unexpected input, malformed requests, and error conditions. Improperly handled errors leak stack traces, internal paths, database schemas, and framework versions — all of which feed downstream attack surface mapping.

This worker is intentionally small (2 stages) because error handling testing is focused: provoke errors, analyze responses.

---

## Pipeline Stages

### Stage 1: error_codes (Section 4.8.1)

**Objective:** Map the application's HTTP error response behavior across all status codes and error conditions. Identify information leakage in error pages.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| ErrorProber | New | LIGHT | Systematically triggers error conditions and catalogs responses. **404 testing:** Requests non-existent paths with various extensions (`.php`, `.asp`, `.jsp`, `.html`) to detect technology-specific error pages. **400 testing:** Sends malformed requests (invalid HTTP version, oversized headers, null bytes in URL, invalid URL encoding). **405 testing:** Sends wrong HTTP methods to known endpoints. **413 testing:** Sends oversized request bodies. **500 testing:** Sends inputs designed to trigger server errors (type mismatches, deeply nested JSON, malformed XML, SQL-like strings in unexpected parameters). For each error response: records status code, response headers, body content, whether a custom error page is shown vs framework default. Compares error page content against known framework error page signatures (Django debug page, Rails exception page, ASP.NET yellow screen, Spring Boot Whitelabel, Express default handler). Each information leak stored as a Vulnerability record. |

**Outputs:** Vulnerability records (information leakage in error pages), Observation records (error behavior inventory).

---

### Stage 2: stack_traces (Section 4.8.2)

**Objective:** Specifically test for stack trace exposure in error responses, which reveals internal file paths, library versions, and code structure.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| StackTraceDetector | New | LIGHT | Complements ErrorProber with targeted stack trace extraction. Analyzes all error responses collected in stage 1 plus generates additional error-inducing requests. **Detection patterns:** Java stack traces (`at com.example.Class.method(File.java:123)`), Python tracebacks (`File "/path/to/file.py", line 123`), .NET stack traces (`at Namespace.Class.Method() in path\file.cs:line 123`), PHP errors (`Fatal error: ... in /path/file.php on line 123`), Node.js traces (`at Object.<anonymous> (/path/file.js:123:45)`), Ruby traces (`/path/file.rb:123:in 'method'`). Extracts structured data from stack traces: internal file paths, library names and versions, database table names, SQL query fragments, configuration values. Each stack trace with sensitive data stored as a Vulnerability record with extracted details. |

**Outputs:** Vulnerability records (stack trace exposure with extracted sensitive details).

---

## Concurrency Configuration

```python
# workers/error_handling/concurrency.py

HEAVY_LIMIT = 2
LIGHT_LIMIT = cpu_count()

TOOL_WEIGHTS = {
    "ErrorProber": "LIGHT",
    "StackTraceDetector": "LIGHT",
}
```

---

## Base Tool Class

```python
# workers/error_handling/base_tool.py

class ErrorHandlingTool(ABC):
    """Abstract base for all error_handling tools.

    Adds error-specific helpers:
    - detect_framework_error_page() -- match response against known error page signatures
    - extract_stack_trace() -- parse stack traces from response bodies
    - classify_information_leak() -- categorize leaked data (path, version, query, credential)
    """
    worker_type = "error_handling"
```

---

## Interaction with Traffic Proxy

Does not use the traffic proxy. Error handling tests are direct HTTP requests with malformed input — no request manipulation needed.

---

# Part B: Cryptography Worker (Section 4.9)

**Worker Directory:** `workers/cryptography/`
**Queue:** `cryptography_queue`
**Trigger:** config_mgmt complete (parallel with error_handling)
**WSTG Section:** 4.9 Cryptography

---

## Overview

The cryptography worker validates the application's use of encryption, hashing, and secure transport. It tests TLS configuration, identifies weak cipher usage, and checks for cryptographic implementation flaws that could allow data interception or manipulation.

---

## Pipeline Stages

### Stage 1: tls_testing (Section 4.9.1)

**Objective:** Validate TLS configuration — supported protocols, cipher suites, certificate validity, and known TLS vulnerabilities.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| TlsAuditor | New | LIGHT | Comprehensive TLS analysis for each HTTPS endpoint. **Protocol support:** Tests SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3. Flags anything below TLS 1.2 as HIGH vulnerability, TLS 1.0/1.1 as MEDIUM (deprecated but sometimes required for compatibility). **Cipher suites:** Enumerates all accepted ciphers, flags NULL ciphers (no encryption), EXPORT ciphers (weak 40/56-bit), DES/3DES (weak), RC4 (biased), anonymous ciphers (no authentication). **Certificate checks:** Expiration date, CN/SAN matching, CA trust chain, key size (RSA < 2048 or ECC < 256 flagged), signature algorithm (SHA-1 flagged). **Known vulnerabilities:** Tests for BEAST (CBC in TLS 1.0), POODLE (SSLv3 fallback), DROWN (SSLv2 cross-protocol), Heartbleed (OpenSSL TLS heartbeat), ROBOT (RSA key exchange oracle), CRIME (TLS compression), Lucky13 (CBC timing). **Forward secrecy:** Checks if ECDHE or DHE cipher suites are preferred. Wraps testssl.sh or sslyze for the heavy lifting. Each issue stored as a Vulnerability record with severity based on exploitability. |

**Outputs:** Vulnerability records (TLS issues), Observation records (full TLS configuration).

---

### Stage 2: padding_oracle (Section 4.9.2)

**Objective:** Test for padding oracle vulnerabilities in encrypted parameters (cookies, tokens, URL parameters) that use block cipher modes like CBC.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| PaddingOracleTester | New | LIGHT | Identifies encrypted parameters (session tokens, viewstate, custom encrypted cookies) and tests for padding oracle behavior. **Detection method:** Modifies the last block of encrypted values and observes response differences — a padding oracle exists when the server returns different errors for valid vs invalid padding (e.g., 200 vs 500, different error messages, different response times). Tests common targets: `ASP.NET ViewState`, `__EVENTVALIDATION`, encrypted cookies, JWT tokens using `A128CBC-HS256`. Rate-limited to avoid account lockouts. Each confirmed oracle stored as a CRITICAL Vulnerability record — padding oracles enable full decryption of encrypted data without the key. |

**Outputs:** Vulnerability records (padding oracle vulnerabilities).

---

### Stage 3: plaintext_transmission (Section 4.9.3)

**Objective:** Identify sensitive data transmitted over unencrypted channels.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| PlaintextLeakScanner | New | LIGHT | Checks all discovered endpoints for plaintext transmission of sensitive data. **HTTP endpoints:** Identifies forms (especially login forms) that submit to HTTP (not HTTPS) URLs. **Mixed content:** Checks HTTPS pages that load resources over HTTP — scripts, stylesheets, fonts, images. **Sensitive form analysis:** Detects password fields, credit card fields, SSN fields that submit to non-HTTPS endpoints. **Cookie flags:** Checks if cookies containing session tokens or sensitive data have the `Secure` flag set. **API endpoints:** Tests if API endpoints accept requests over HTTP (not just HTTPS). Each plaintext transmission path stored as a Vulnerability record with severity based on data sensitivity (credentials to CRITICAL, PII to HIGH, other to MEDIUM). |

**Outputs:** Vulnerability records (plaintext transmission paths).

---

### Stage 4: weak_crypto (Section 4.9.4)

**Objective:** Identify weak cryptographic algorithms and implementations used by the application — beyond TLS (which is covered in stage 1).

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| AlgorithmAuditor | New | LIGHT | Analyzes application-level cryptographic usage. **Password hashing:** Tests registration and password reset flows to infer hashing algorithms — fast response times suggest weak hashing (MD5, SHA-1, unsalted SHA-256). Checks for bcrypt/scrypt/argon2id indicators in timing. **Token analysis:** Examines CSRF tokens, password reset tokens, API keys for entropy and structure. Low entropy tokens suggest weak random number generators. Sequential tokens suggest predictable generation. **JWT analysis:** Decodes JWT headers and payloads. Flags `alg: "none"`, `alg: "HS256"` with a weak or guessable key, RSA keys < 2048 bits. Tests for algorithm confusion (change RS256 to HS256 and sign with public key). **Cookie encryption:** Analyzes encrypted cookie values for block size patterns suggesting DES/3DES, detects ECB mode via duplicate blocks in long values. Each weak algorithm stored as a Vulnerability record. |

**Outputs:** Vulnerability records (weak cryptographic implementations).

---

## Concurrency Configuration

```python
# workers/cryptography/concurrency.py

HEAVY_LIMIT = 2
LIGHT_LIMIT = cpu_count()

TOOL_WEIGHTS = {
    "TlsAuditor": "LIGHT",
    "PaddingOracleTester": "LIGHT",
    "PlaintextLeakScanner": "LIGHT",
    "AlgorithmAuditor": "LIGHT",
}
```

---

## Interaction with Traffic Proxy

Stage 2 (padding_oracle) optionally routes through the traffic proxy to log full request/response pairs for PoC documentation. Other stages do not need the proxy.

---

# Part C: Business Logic Worker (Section 4.10)

**Worker Directory:** `workers/business_logic/`
**Queue:** `business_logic_queue`
**Trigger:** authorization AND session_mgmt complete
**WSTG Section:** 4.10 Business Logic Testing

---

## Overview

The business_logic worker tests for flaws in the application's workflow and validation logic. Unlike input_validation (which tests generic injection vectors), business logic testing targets application-specific behavior — can workflows be bypassed? Can validation be circumvented by manipulating request sequences? Can business rules be abused?

This is the most context-dependent worker. It relies heavily on the entry points, parameters, and authenticated session data gathered by upstream workers.

---

## Pipeline Stages

### Stage 1: data_validation (Section 4.10.1)

**Objective:** Test whether the application validates business data according to its rules — range checks, format validation, consistency checks.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| BusinessValidationTester | New | LIGHT | Tests form inputs and API parameters for business logic validation bypass. **Boundary testing:** Negative quantities in shopping carts, zero-amount payments, dates in the past for future-only fields, ages outside valid range. **Type confusion:** String where integer expected, arrays where string expected, null values. **Precision abuse:** Floating-point quantities (0.001 items), extremely large numbers, scientific notation. **Currency manipulation:** Negative prices, mismatched currency codes, decimal precision overflow. **Encoding bypass:** Unicode equivalents (fullwidth digits), URL encoding, double encoding. Tests are parameter-specific — uses Parameter records from info_gathering to target only fields that represent business data (quantities, prices, dates, identifiers). Each bypass stored as a Vulnerability record. |

**Outputs:** Vulnerability records (validation bypass).

---

### Stage 2: request_forgery (Section 4.10.2)

**Objective:** Test whether forged requests with valid structure but invalid business context are accepted.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| RequestForgeryTester | New | LIGHT | Replays captured requests with modified business-critical parameters. **ID substitution:** Replaces order IDs, transaction IDs, user IDs in requests with the Testing User's identifiers or non-existent values. **Status manipulation:** Attempts to change order status directly (pending to shipped), approve own requests, escalate priority levels. **Workflow skip:** Submits step 3 of a multi-step process without completing steps 1-2. **Privilege parameters:** Adds `role=admin`, `is_admin=true`, `access_level=5` to normal requests. **Price manipulation:** Replays checkout requests with modified price parameters. Uses authenticated Tester session for all requests. Each accepted forged request stored as a Vulnerability record. |

**Outputs:** Vulnerability records (forged request acceptance).

---

### Stage 3: integrity_checks (Section 4.10.3)

**Objective:** Test whether the application maintains data integrity across operations — checksums, hashes, HMACs that can be manipulated.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| IntegrityTester | New | LIGHT | Identifies and tests integrity mechanisms. **HMAC parameters:** Detects `sig`, `signature`, `hash`, `hmac`, `checksum`, `token` parameters in requests. Tests if removing them still processes the request. Tests if modifying the protected data while keeping the old signature is accepted (missing re-validation). **ViewState:** Decodes ASP.NET ViewState, modifies values, checks if the MAC is validated. **Hidden field manipulation:** Modifies hidden form fields (prices, discount codes, user IDs) and submits. **File integrity:** Uploads files with mismatched Content-Type vs actual content. **Transaction integrity:** Tests if completing a transaction twice processes payment twice (idempotency check). Each integrity failure stored as a Vulnerability record. |

**Outputs:** Vulnerability records (integrity check failures).

---

### Stage 4: process_timing (Section 4.10.4)

**Objective:** Test for timing-based vulnerabilities — race conditions, TOCTOU (time-of-check-time-of-use) bugs, and business logic that depends on timing assumptions.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| TimingAnalyzer | New | LIGHT | Tests for race conditions and timing-dependent behavior. **Race conditions:** Sends concurrent identical requests to exploit TOCTOU gaps — double-spending (apply coupon twice), double-withdrawal, double-vote. Uses `asyncio.gather` to fire 5-10 simultaneous requests. **Timing attacks:** Measures response time differences for valid vs invalid inputs (username enumeration via login timing, valid vs invalid coupon codes, existing vs non-existing resources). Uses statistical analysis (multiple samples, standard deviation thresholds) to reduce false positives. **Sequence breaking:** Attempts to perform actions before prerequisite conditions are met (checkout before adding items, reset password before requesting reset link, access premium content before payment). Each confirmed timing issue stored as a Vulnerability record. |

**Outputs:** Vulnerability records (race conditions, timing attacks).

---

### Stage 5: rate_limiting (Section 4.10.5)

**Objective:** Test the effectiveness of rate limiting and throttling mechanisms on critical functionality.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| RateLimitTester | New | LIGHT | Tests rate limiting on security-critical endpoints. **Login:** Sends 20 rapid login attempts with wrong passwords — checks if lockout or throttling engages. **Password reset:** Sends 10 rapid reset requests for the Testing User's email — checks if rate limiting exists. **API endpoints:** Sends 50 rapid requests to each discovered API endpoint — checks for 429 responses. **Registration:** Attempts rapid account creation — checks for CAPTCHA or throttling. **Search/export:** Tests if resource-intensive operations (search, CSV export, PDF generation) have rate limits. For each endpoint: measures the threshold (how many requests before limiting), the response (429, CAPTCHA, block, nothing), the recovery time (how long until rate limit resets). Missing rate limiting on critical endpoints stored as Vulnerability records (login to HIGH, API to MEDIUM, other to LOW). |

**Outputs:** Vulnerability records (missing or weak rate limiting).

---

### Stage 6: workflow_bypass (Section 4.10.6)

**Objective:** Test if multi-step business processes can be bypassed by skipping, reordering, or replaying steps.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| WorkflowBypassTester | New | LIGHT | Maps multi-step workflows and tests for bypass. **Workflow detection:** Identifies multi-step processes from form sequences (registration wizards, checkout flows, onboarding, application submissions). Maps step URLs and their expected order. **Skip testing:** Directly requests step N without completing steps 1 through N-1. **Reorder testing:** Completes steps out of order (step 3, then step 1, then step 2). **Replay testing:** Replays a completed step with modified parameters after the workflow is finished. **Back button abuse:** Navigates back to previous steps after completion and resubmits with different data. **Partial completion:** Submits required steps but skips optional validation steps (email verification, phone verification, CAPTCHA). Each successful bypass stored as a Vulnerability record with full step sequence PoC. |

**Outputs:** Vulnerability records (workflow bypass).

---

### Stage 7: application_misuse (Section 4.10.7)

**Objective:** Test for application misuse scenarios — using legitimate features in unintended ways that cause harm.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| MisuseTester | New | LIGHT | Tests legitimate features for abuse potential. **Email functionality:** If the app sends emails (invitations, notifications, sharing), tests if it can be used as a spam relay by sending to arbitrary addresses (uses Testing User's email only). **Referral/reward abuse:** Tests if referral codes can be self-applied, if rewards can be claimed multiple times. **Export abuse:** Tests if data export features can be used to extract large datasets (enumeration via export). **Notification abuse:** Tests if notification features can be weaponized (mass notifications, notification to arbitrary users — tested against Testing User only). **Comment/review abuse:** Tests if review systems accept reviews without purchase, if comments can impersonate other users. All testing targets Testing User only. Each confirmed misuse vector stored as a Vulnerability record. |

**Outputs:** Vulnerability records (application misuse vectors).

---

### Stage 8: file_upload_validation (Section 4.10.8)

**Objective:** Test file upload functionality for type validation bypass.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| FileTypeTester | New | LIGHT | Tests file upload endpoints for content-type and extension validation. **Extension bypass:** Double extensions (`file.php.jpg`), null byte injection (`file.php%00.jpg`), case variation (`file.PHP`), alternative extensions (`.phtml`, `.pht`, `.php5`, `.shtml`). **MIME bypass:** Correct extension with wrong MIME type, wrong extension with correct MIME type. **Magic bytes:** Files with correct magic bytes but wrong extension (polyglot files). **Size limits:** Oversized files to test for DoS, zero-byte files, files at exact size boundaries. **Content validation:** Files that pass extension/MIME checks but contain executable content (PHP in EXIF data, script tags in SVG, XXE in XLSX). Tests each upload endpoint discovered by info_gathering. Each bypass stored as a Vulnerability record with the specific technique that succeeded. |

**Outputs:** Vulnerability records (file upload validation bypass).

---

### Stage 9: malicious_file_upload (Section 4.10.9)

**Objective:** Test if uploaded files can achieve code execution, XSS, or other impacts on the server.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| MaliciousUploadTester | New | LIGHT | Uploads test files designed to achieve specific impacts, then checks if they execute. **Web shell test:** Uploads a minimal PHP/ASP/JSP test file that outputs a unique string (not a real shell — just `<?php echo 'UPLOAD_TEST_STRING'; ?>`). Checks if accessing the uploaded file executes the code. **XSS via upload:** Uploads HTML/SVG files containing benign JavaScript markers. Checks if the file is served with a content-type that allows script execution. **SSRF via upload:** Uploads files that reference internal URLs (SVG with external entity, XLSX with external reference) and checks for callbacks via the callback server. **Path traversal:** Attempts to upload to parent directories via filename manipulation (`../../../etc/test.txt`). **Overwrite:** Attempts to overwrite existing files (upload a file named `index.html`). Uses callback server to detect blind execution. Each successful upload impact stored as a CRITICAL or HIGH Vulnerability record. |

**Outputs:** Vulnerability records (file upload exploitation).

---

## Concurrency Configuration

```python
# workers/business_logic/concurrency.py

HEAVY_LIMIT = 2
LIGHT_LIMIT = cpu_count()

TOOL_WEIGHTS = {
    "BusinessValidationTester": "LIGHT",
    "RequestForgeryTester": "LIGHT",
    "IntegrityTester": "LIGHT",
    "TimingAnalyzer": "LIGHT",
    "RateLimitTester": "LIGHT",
    "WorkflowBypassTester": "LIGHT",
    "MisuseTester": "LIGHT",
    "FileTypeTester": "LIGHT",
    "MaliciousUploadTester": "LIGHT",
}
```

---

## Interaction with Traffic Proxy

Stages 2 (request_forgery) and 3 (integrity_checks) route through the traffic proxy for request capture and parameter manipulation. The proxy's Rule Manager is used to set up parameter replacement rules for automated testing across multiple endpoints.

## Interaction with Callback Server

Stage 9 (malicious_file_upload) registers callbacks for blind execution detection — SSRF via uploaded files, blind code execution confirmation.

---

# Part D: Client-Side Worker (Section 4.11)

**Worker Directory:** `workers/client_side/`
**Queue:** `client_side_queue`
**Trigger:** config_mgmt complete (parallel with business_logic)
**WSTG Section:** 4.11 Client-Side Testing

---

## Overview

The client_side worker tests for vulnerabilities that execute in the user's browser context. This is the largest worker by stage count (13 stages) and heavily uses a shared browser instance for DOM analysis and JavaScript execution testing.

### BrowserManager Singleton

Client-side testing requires a headless browser for DOM interaction. A shared `BrowserManager` provides a Playwright Chromium instance:

```python
# workers/client_side/browser_manager.py

class BrowserManager:
    """Singleton Playwright browser for client-side testing.

    Manages a single Chromium instance shared across all client_side stages.
    Each tool gets an isolated BrowserContext (separate cookies, storage).
    """

    _instance = None
    _browser = None

    @classmethod
    async def get_browser(cls):
        if cls._browser is None:
            playwright = await async_playwright().start()
            cls._browser = await playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
        return cls._browser

    @classmethod
    async def new_context(cls):
        browser = await cls.get_browser()
        return await browser.new_context()

    @classmethod
    async def cleanup(cls):
        if cls._browser:
            await cls._browser.close()
            cls._browser = None
```

---

## Pipeline Stages

### Stage 1: dom_xss (Section 4.11.1)

**Objective:** Identify DOM-based cross-site scripting vulnerabilities where user input flows through JavaScript into dangerous DOM sinks without sanitization.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| DomSinkAnalyzer | New | HEAVY | Uses the BrowserManager to load pages and trace JavaScript execution. **Source-sink analysis:** Instruments the browser to monitor data flow from DOM sources (`location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` data, `localStorage`/`sessionStorage` reads) to dangerous sinks (`.innerHTML` assignment, DOM write APIs, `setTimeout`/`setInterval` with string arguments, `Function()` constructor, `setAttribute()` on event handlers, `$.html()` jQuery calls, framework-specific unsafe rendering patterns). **Taint tracking:** Injects unique marker strings into each source and checks if they appear unescaped in sink operations. **Payload testing:** For confirmed source-to-sink flows, tests with XSS payloads to verify exploitability. Uses Playwright page instrumentation to intercept JavaScript execution. Each confirmed DOM XSS stored as a CRITICAL Vulnerability record with full source-to-sink trace. |

**Outputs:** Vulnerability records (DOM XSS with source-sink mapping).

---

### Stage 2: js_execution (Section 4.11.2)

**Objective:** Test for JavaScript execution vulnerabilities beyond DOM XSS — JavaScript injection in non-HTML contexts, JSON injection, and callback manipulation.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| JsExecutionTester | New | LIGHT | Tests for JavaScript execution in non-standard contexts. **JSONP injection:** Identifies JSONP endpoints (callback parameters in URLs) and tests if the callback name can contain arbitrary JavaScript. **JSON injection:** Tests API endpoints that return JSON with user-controlled values for unescaped content that breaks out of JSON context when consumed by client-side code. **JavaScript template injection:** Tests client-side template engines (AngularJS expressions, Vue interpolation, Mustache templates) for expression injection. **Script gadgets:** Identifies script gadget chains in popular libraries (jQuery, Prototype, Dojo) that can be exploited for XSS bypass even with CSP. Uses browser context for dynamic analysis. Each confirmed execution path stored as a Vulnerability record. |

**Outputs:** Vulnerability records (JavaScript execution vectors).

---

### Stage 3: html_injection (Section 4.11.3)

**Objective:** Test for HTML injection vulnerabilities that allow injecting arbitrary HTML content (but not necessarily JavaScript).

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| HtmlInjectionTester | New | LIGHT | Tests all reflected and stored input points for HTML injection. **Reflected HTML:** Injects benign HTML tags (`<b>`, `<u>`, `<img>`) into parameters and checks if they render in the response. **Stored HTML:** Submits HTML content through forms and checks if it persists and renders on subsequent page loads. **Context analysis:** Determines injection context (inside tag attribute, inside tag body, inside script string, inside CSS, inside comment) and tests context-appropriate breakout sequences. **Filter bypass:** Tests common filter bypass techniques (mixed case, null bytes, alternative encodings, entity encoding, SVG/MathML namespace). HTML injection without script execution stored as MEDIUM; with script execution escalated to HIGH/CRITICAL as XSS. |

**Outputs:** Vulnerability records (HTML injection).

---

### Stage 4: open_redirect (Section 4.11.4)

**Objective:** Identify open redirect vulnerabilities that can be used for phishing or authentication token theft.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| OpenRedirectTester | New | LIGHT | Tests all parameters that influence navigation (redirect URLs, return URLs, next URLs, callback URLs). **Parameter detection:** Identifies redirect parameters by name (`url`, `redirect`, `next`, `return`, `returnUrl`, `continue`, `dest`, `destination`, `redir`, `redirect_uri`, `return_to`, `go`, `out`, `forward`) and by value (any parameter whose value looks like a URL). **Payload testing:** Tests with external domains, protocol-relative URLs (`//evil.com`), data URIs, JavaScript URIs, URL-encoded variants, double-URL-encoded variants, backslash variants, authentication bypass patterns (`target.com@evil.com`). Follows redirects to verify the final destination. Open redirects in login/OAuth flows rated HIGH; others rated MEDIUM. Each confirmed redirect stored as a Vulnerability record with the working payload. |

**Outputs:** Vulnerability records (open redirects with payload).

---

### Stage 5: css_injection (Section 4.11.5)

**Objective:** Test for CSS injection vulnerabilities that can be used for data exfiltration or UI manipulation.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CssInjectionTester | New | LIGHT | Tests for CSS injection in style attributes, style tags, and CSS files. **Injection points:** Parameters reflected in `style` attributes, `<style>` blocks, or CSS files. **Exfiltration payloads:** CSS attribute selectors that leak data character-by-character (`input[value^="a"] { background: url(callback/a) }`), `@import` pointing to attacker-controlled stylesheets, `@font-face` with external source. **UI redress:** CSS that hides legitimate content and displays fake content (login form phishing). Uses callback server for blind CSS injection detection. Each confirmed injection stored as a Vulnerability record. |

**Outputs:** Vulnerability records (CSS injection).

---

### Stage 6: resource_manipulation (Section 4.11.6)

**Objective:** Test for client-side resource manipulation — can an attacker control which resources the application loads?

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| ResourceManipulationTester | New | LIGHT | Tests whether user-controllable input influences resource loading. **Script src manipulation:** Parameters reflected in script `src` attributes. **Link href manipulation:** Parameters reflected in stylesheet `href` attributes. **Image src manipulation:** Parameters reflected in image `src` attributes (lower severity). **Object/embed manipulation:** Parameters reflected in object `data` or embed `src` attributes. **Import map manipulation:** Tests if import maps can be influenced via URL parameters. For each discovered manipulation: tests if the parameter can point to an external domain, tests if Content Security Policy blocks the load, documents the bypass if CSP allows it. Each confirmed manipulation stored as a Vulnerability record with severity based on resource type (script to CRITICAL, stylesheet to HIGH, image to LOW). |

**Outputs:** Vulnerability records (resource manipulation).

---

### Stage 7: cors_testing (Section 4.11.7)

**Objective:** Test Cross-Origin Resource Sharing (CORS) configuration for misconfigurations that allow unauthorized cross-origin data access.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| CorsTester | New | LIGHT | Comprehensive CORS misconfiguration testing. **Origin reflection:** Sends requests with `Origin: https://evil.com` and checks if the response reflects it in `Access-Control-Allow-Origin`. **Null origin:** Tests `Origin: null` (allowed by iframes with sandboxed documents). **Subdomain wildcard:** Tests `Origin: https://evil.target.com` to check for suffix matching. **Protocol downgrade:** Tests `Origin: http://target.com` (HTTP instead of HTTPS). **Credential leakage:** Checks if `Access-Control-Allow-Credentials: true` is combined with reflected origins (enables cookie-based cross-origin data theft). **Preflight bypass:** Tests simple requests that bypass preflight (GET with specific content-types) on endpoints that return sensitive data. **Internal header exposure:** Checks `Access-Control-Expose-Headers` for sensitive custom headers. Each misconfiguration stored as a Vulnerability record with severity based on credential exposure (with credentials to CRITICAL, without to HIGH). |

**Outputs:** Vulnerability records (CORS misconfigurations).

---

### Stage 8: flash_crossdomain (Section 4.11.8)

**Objective:** Test for legacy Flash and Silverlight cross-domain policy misconfigurations. While Flash is deprecated, many applications still serve permissive `crossdomain.xml` files.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| FlashAuditor | New | LIGHT | Lightweight check for legacy cross-domain policy files. **crossdomain.xml:** Checks for `allow-access-from domain="*"`, overly permissive domain patterns, `secure="false"` on HTTPS sites. **clientaccesspolicy.xml:** Same analysis for Silverlight equivalent. **SWF files:** Scans discovered paths for `.swf` files — if found, downloads and decompiles to check for hardcoded credentials, SSRF endpoints, or other vulnerabilities (even though Flash Player is dead, SWF files on the server may contain secrets). Stores findings as Observation records (informational for deprecated tech) unless permissive policy combined with active functionality (then Vulnerability). |

**Outputs:** Observation records (legacy policy files), Vulnerability records (if actively exploitable).

---

### Stage 9: clickjacking (Section 4.11.9)

**Objective:** Test whether the application can be framed by an attacker for clickjacking attacks.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| ClickjackTester | New | LIGHT | Tests framing protection on all critical pages. **X-Frame-Options:** Checks for `DENY` or `SAMEORIGIN` on each page. Flags missing headers. **CSP frame-ancestors:** Checks `Content-Security-Policy` for `frame-ancestors` directive. Flags missing or permissive (`frame-ancestors *`). **JavaScript frame busting:** Detects JavaScript-based frame protection and tests bypass techniques (sandboxed iframes with `allow-scripts allow-top-navigation`, double framing). **Page-specific testing:** Prioritizes pages with state-changing actions (forms, buttons, links) over static content. A login page without framing protection is HIGH; a static about page is INFO. **PoC generation:** For vulnerable pages, generates a proof-of-concept HTML page that demonstrates the clickjacking with the target framed and a transparent overlay. Each unprotected critical page stored as a Vulnerability record. |

**Outputs:** Vulnerability records (clickjacking with PoC HTML).

---

### Stage 10: websocket_testing (Section 4.11.10)

**Objective:** Test WebSocket connections for authentication, authorization, and injection vulnerabilities.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| WebSocketAuditor | New | HEAVY | Full WebSocket security testing using the BrowserManager. **Discovery:** Identifies WebSocket endpoints from JavaScript source analysis (`new WebSocket(...)` patterns), network traffic monitoring, and known WebSocket paths (`/ws`, `/socket`, `/cable`, `/hub`). **Authentication:** Tests if WebSocket connections require authentication — connects without credentials and checks if messages are accepted. **Cross-origin:** Tests if WebSocket connections from arbitrary origins are accepted (no Origin header validation). **Injection:** Sends JSON payloads with injection strings (XSS, SQLi, command injection patterns) through WebSocket messages. **Message manipulation:** Intercepts and modifies WebSocket messages via the browser's DevTools Protocol — replays messages with modified parameters, sends messages out of expected sequence. **DoS:** Tests if sending a large volume of messages or oversized messages crashes the server or degrades performance. Each issue stored as a Vulnerability record with the specific WebSocket endpoint and payload. |

**Outputs:** Vulnerability records (WebSocket security issues).

---

### Stage 11: postmessage_testing (Section 4.11.11)

**Objective:** Test the security of cross-document messaging (postMessage API) for origin validation and data handling.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| PostMessageTester | New | HEAVY | Uses BrowserManager to analyze postMessage usage. **Listener discovery:** Instruments pages to detect all message event listeners. Extracts the handler code to determine: does it check the event origin? Does it use the event data in dangerous sinks? **Origin bypass:** If origin checking exists, tests for bypass (regex flaws, substring matching instead of exact match, null origin acceptance). **Message injection:** Sends crafted postMessage events from a controlled iframe to test if the handler accepts and processes them without proper origin validation. **Data flow tracing:** Traces event data usage — if it flows into DOM manipulation sinks or navigation targets, tests with XSS payloads. **Cross-window communication:** Checks if sensitive data (tokens, user info) is sent via postMessage to windows that could be controlled by an attacker. Each confirmed issue stored as a Vulnerability record. |

**Outputs:** Vulnerability records (postMessage vulnerabilities).

---

### Stage 12: browser_storage (Section 4.11.12)

**Objective:** Test for sensitive data stored in client-side storage mechanisms (localStorage, sessionStorage, IndexedDB, cookies).

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| StorageAuditor | New | HEAVY | Uses BrowserManager to inspect all client-side storage after browsing key application pages. **localStorage/sessionStorage:** Dumps all keys and values. Scans for sensitive data: JWTs, API keys, user PII, authentication tokens, internal URLs, passwords, credit card numbers. Checks if tokens in storage are properly cleared on logout. **IndexedDB:** Lists all databases and object stores. Samples records for sensitive data patterns. **Cookies:** Dumps all cookies. Checks flags: `HttpOnly` (missing means accessible to XSS), `Secure` (missing means sent over HTTP), `SameSite` (missing means CSRF risk), `Path` and `Domain` scope (overly broad means data leaks to subdomains). **Cache storage:** Checks Service Worker caches for sensitive API responses being cached. **Credential persistence:** Logs in via Tester session, closes browser context, opens new context — checks if credentials persist inappropriately. Each sensitive data exposure stored as a Vulnerability record. |

**Outputs:** Vulnerability records (sensitive data in client storage).

---

### Stage 13: cross_site_script_inclusion (Section 4.11.13)

**Objective:** Test for Cross-Site Script Inclusion (XSSI) — sensitive data accessible via script tags from cross-origin pages.

**Tools:**

| Tool | Status | Weight | Description |
|------|--------|--------|-------------|
| XssiTester | New | LIGHT | Tests for data leakage through cross-origin script inclusion. **Dynamic JavaScript endpoints:** Identifies endpoints that return JavaScript with user-specific data (JSONP, dynamic JS configuration, user-specific script files). **Override testing:** For JSON/JavaScript responses, tests if they can be captured by overriding JavaScript built-ins: Array constructor override (for JSON arrays), object setter override (for JSON objects), prototype pollution for data extraction. **Authentication-dependent responses:** Loads JavaScript/JSON endpoints from an unauthenticated context and an authenticated context — if the authenticated version contains additional data, the endpoint leaks data via script tag inclusion. **CSP bypass:** Checks if Content Security Policy `script-src` allows the target's own origin (self) — if so, XSSI attacks from same-origin pages are possible. Each confirmed XSSI vector stored as a Vulnerability record. |

**Outputs:** Vulnerability records (XSSI data leakage).

---

## Concurrency Configuration

```python
# workers/client_side/concurrency.py

HEAVY_LIMIT = 2
LIGHT_LIMIT = cpu_count()

TOOL_WEIGHTS = {
    "DomSinkAnalyzer": "HEAVY",
    "JsExecutionTester": "LIGHT",
    "HtmlInjectionTester": "LIGHT",
    "OpenRedirectTester": "LIGHT",
    "CssInjectionTester": "LIGHT",
    "ResourceManipulationTester": "LIGHT",
    "CorsTester": "LIGHT",
    "FlashAuditor": "LIGHT",
    "ClickjackTester": "LIGHT",
    "WebSocketAuditor": "HEAVY",
    "PostMessageTester": "HEAVY",
    "StorageAuditor": "HEAVY",
    "XssiTester": "LIGHT",
}
```

---

## Base Tool Class

```python
# workers/client_side/base_tool.py

class ClientSideTool(ABC):
    """Abstract base for all client_side tools.

    Adds client-side-specific helpers:
    - get_browser_context() -- returns an isolated Playwright BrowserContext
    - inject_script() -- inject instrumentation JavaScript into pages
    - extract_dom_state() -- capture current DOM state for analysis
    - trace_js_execution() -- monitor JavaScript execution via CDP
    """
    worker_type = "client_side"

    async def get_browser_context(self):
        """Get a fresh, isolated browser context from the BrowserManager."""
        return await BrowserManager.new_context()
```

---

## Interaction with Traffic Proxy

Stages 1 (dom_xss), 2 (js_execution), and 10 (websocket_testing) optionally route through the traffic proxy for request/response logging and payload injection.

## Interaction with Callback Server

Stage 5 (css_injection), stage 6 (resource_manipulation), and stage 9 (clickjacking — for PoC hosting) use the callback server for out-of-band detection.
