# API Testing Worker

Act as a Senior API Security Researcher.
Task: Create the "API-Testing-Engine" Dockerized worker. This container specializes in discovering, mapping, and testing REST, GraphQL, and SOAP interfaces.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Go and Python 3.10+.
- **Primary Tools**:
    - **Kiterunner**: For ultra-fast API endpoint brute-forcing using API-specific wordlists.
    - **Akamai/Arjun**: For deep parameter discovery.
    - **GraphQLmap / InQL**: For GraphQL introspection and query testing.
    - **graphql-cop**: For GraphQL security misconfiguration detection (batching DoS, field suggestion info leak, introspection in prod).
    - **Postman-to-k6 / Newman**: To execute automated API collections if found.
    - **TruffleHog**: To scan API documentation (Swagger/OpenAPI) for hardcoded keys.
    - **jwt_tool**: For JWT algorithm confusion, key brute-force, claim tampering, JWK injection, and kid path traversal.
    - **nosqlmap**: For MongoDB/CouchDB operator injection, authentication bypass, and data extraction.
    - **CORScanner**: For CORS misconfiguration testing (origin reflection, null origin, subdomain wildcard, credential leakage).

## 2. API Discovery & Mapping

- **Input**: Query the `assets` table (type='url') for keywords like `/api/`, `/v1/`, `/graphql`, `/swagger.json`, or `/openapi.yaml`.
- **Intelligent Brute-forcing**:
    - Run **Kiterunner** using the `routes-large.kite` dataset against discovered API roots.
    - If a GraphQL endpoint is found, attempt **Introspection** to map the entire schema (Queries, Mutations, and Types).
- **Schema Analysis**: If a Swagger/OpenAPI spec is found, parse it to identify every available method (GET, POST, PUT, DELETE) and required headers.

## 3. Execution Strategy (4-Stage Pipeline)

Implement a Python controller that executes four sequential stages:

### Stage 1: `api_discovery`
- Kiterunner brute-forcing against discovered API roots.
- Swagger/OpenAPI spec parsing — identify all methods, paths, required parameters.
- GraphQL introspection via GraphQLmap/InQL — map queries, mutations, types.
- TruffleHog scan on API documentation for hardcoded keys.
- Write the full API tree (Path + Method + Required Params) to a specialized `api_schemas` table.

### Stage 2: `auth_testing` (concurrent)
- **jwt_tool**: Detect JWT tokens in `observations.headers` where `Authorization: Bearer` contains 3 base64 dot-separated segments. Test: algorithm confusion (none, HS256↔RS256), key brute-force (rockyou), claim tampering (sub, role, exp), JWK injection, kid path traversal. Write JWT bypass findings to `vulnerabilities` with manipulated token as PoC.
- **OAuth Testing** (custom Python tool): Target `assets` (type='url') where path matches `/oauth/`, `/authorize`, `/callback`, `/auth/`, `/login`, or `observations.headers` contains OAuth-related response headers. Test: authorization code flow manipulation, state parameter CSRF, redirect_uri validation bypass, token leakage in referrer, scope escalation, PKCE downgrade. Write OAuth flow vulns to `vulnerabilities`.
- **CORScanner**: Target all `assets` (type='url') containing `/api/` paths. Test: Origin reflection, null origin trust, subdomain wildcard, credential leakage via `Access-Control-Allow-Credentials: true`. Write CORS misconfig findings to `vulnerabilities`.

### Stage 3: `injection_testing` (concurrent)
- **BOLA/IDOR** (enhanced): Iterate through numeric IDs, UUIDs, and slugs. Test horizontal + vertical privilege escalation by comparing responses across two auth contexts (user A's token → user B's resources). Input from `api_schemas` with path parameters (`:id`, `:userId`, etc.).
- **Mass Assignment** (enhanced): Parse API responses for all returned fields, replay each as writable via PATCH/PUT/POST. Flag role/permission/balance/verified/email_confirmed fields. Input from API write endpoints in `api_schemas`.
- **nosqlmap**: Target `assets` (type='url') containing `/api/` where `observations.tech_stack` shows MongoDB/CouchDB/Express/Node.js. Test: MongoDB operator injection (`$gt`, `$ne`, `$regex`), authentication bypass, data extraction. Write NoSQL injection findings to `vulnerabilities`.

### Stage 4: `abuse_testing` (concurrent)
- **Rate-Limit Testing** (custom Python tool): Burst N identical requests to sensitive endpoints matching login/reset/otp/register/transfer/payment paths. Measure response code/timing drift, detect missing `429`/`Retry-After` headers. Burst count configurable from `target_profile` to stay within scope. Write rate-limit bypass findings to `vulnerabilities` (severity: medium).
- **GraphQL Abuse** (graphql-cop + enhanced): Test GraphQL endpoints discovered in Stage 1 for: batching DoS potential, field suggestion info leakage, introspection enabled in production, query depth/complexity limit testing, mutation abuse. Write GraphQL misconfig findings to `vulnerabilities`.

## 4. Database & Event Reporting

- **API Map Sync**: Write the full API tree (Path + Method + Required Params) to a specialized `api_schemas` table (added to the OAM model).
- **Vulnerability Sync**: Report all findings (BOLA, IDOR, JWT bypass, OAuth flaws, CORS misconfig, NoSQL injection, mass assignment, rate-limit bypass, GraphQL abuse) to the `vulnerabilities` and `alerts` tables.
- **Credential Leakage**: If API keys are found in Swagger docs or JS bundles, log them immediately.
- **Alerting**: Immediate insertion into `alerts` for any finding with Severity >= High.

## 5. Compliance & Headers

- **Custom Headers**: Inject `Authorization: Bearer <token>` or custom API keys found in the `.env` or previous phases.
- **Rate Limiting**: Strictly follow the PPS limits to avoid triggering API circuit breakers.
- **OOS Attacks**: Respect the `oos_attacks` exclusion list — skip DoS-class tests if "No DoS" is specified.

Deliverables: Dockerfile, Kiterunner wrapper, GraphQL analysis script (GraphQLmap + graphql-cop), jwt_tool integration, OAuth testing tool, CORScanner integration, nosqlmap wrapper, rate-limit tester, IDOR/mass-assignment enhanced scripts, and API-schema parsing logic.
