# Phase 8 — API Testing Worker Design Document

**Date:** 2026-03-10
**Scope:** Phase 8 — API-Testing-Engine Dockerized worker

## Overview

The API Testing Worker (`api_worker`) specializes in discovering, mapping, and testing REST, GraphQL, and SOAP interfaces. It runs a 4-stage sequential pipeline with concurrent tools within each stage, following the same `Stage`/`Pipeline`/`BaseTool` pattern established by the vuln_scanner.

### Key Decisions

- **Queue:** `api_queue` / `api_group`
- **Container name:** `api-worker-{hostname}`
- **HTTP client:** `httpx[http2]` for all custom Python tools (async, native HTTP/2)
- **Route discovery:** ffuf with API-specific wordlists (replaces Kiterunner — unmaintained since 2021)
- **New DB table:** `ApiSchema` added to `shared/lib_webbh/database.py`
- **Newman/Postman:** Deferred — rare edge case, can be added later
- **Tool isolation:** All tools fresh in api_worker — no cross-worker imports

## Directory Layout

```
workers/api_worker/
    __init__.py
    base_tool.py          # ApiTestTool(ABC)
    concurrency.py        # WeightClass/semaphore pattern
    pipeline.py           # 4-stage Pipeline class
    main.py               # Queue listener entry point
    tools/
        __init__.py
        ffuf_api_tool.py      # Stage 1: API route brute-forcing
        openapi_parser.py     # Stage 1: Swagger/OpenAPI spec parsing
        graphql_introspect.py # Stage 1: GraphQL introspection
        trufflehog_tool.py    # Stage 1: API doc key scanning
        jwt_tool.py           # Stage 2: JWT testing
        oauth_tester.py       # Stage 2: OAuth flow testing (custom Python)
        cors_scanner.py       # Stage 2: CORS misconfiguration
        idor_tester.py        # Stage 3: BOLA/IDOR testing (custom Python)
        mass_assign_tester.py # Stage 3: Mass assignment (custom Python)
        nosqlmap_tool.py      # Stage 3: NoSQL injection
        rate_limit_tester.py  # Stage 4: Rate-limit bypass (custom Python)
        graphql_cop_tool.py   # Stage 4: GraphQL abuse
```

## Database — `ApiSchema` Model

Added to `shared/lib_webbh/database.py` alongside the existing 10 OAM models:

```python
class ApiSchema(TimestampMixin, Base):
    __tablename__ = "api_schemas"
    __table_args__ = (
        UniqueConstraint("target_id", "asset_id", "method", "path",
                         name="uq_api_schemas_target_asset_method_path"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asset_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(2000))
    params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    auth_required: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    spec_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
```

**Column rationale:**
- `method` + `path` uniquely identify an endpoint per target/asset
- `params` — JSON holding query, body, and header params from different sources
- `auth_required` — flags endpoints that returned 401/403 during discovery
- `spec_type` — provenance: `openapi`, `graphql`, or `discovered`
- `content_type` — expected content type (application/json, application/graphql, etc.)

Relationships added to `Target` (`api_schemas`) and `Asset` (`api_schemas`).

## Base Tool — `ApiTestTool(ABC)`

Mirrors `VulnScanTool` with API-specific query helpers:

```python
class ApiTestTool(ABC):
    name: str
    weight_class: WeightClass

    @abstractmethod
    async def execute(self, target, scope_manager, target_id, container_name, headers=None, **kwargs) -> dict:
        ...
```

**Inherited helpers (same as VulnScanTool):**
- `check_cooldown()` / `update_tool_state()` — JobState-based cooldown
- `run_subprocess()` — async subprocess with timeout
- `_save_vulnerability()` / `_create_alert()` — vuln persistence + alerting
- `_save_asset()` — scope-checked asset upsert
- `_get_all_url_assets()` / `_get_live_urls()` — asset queries
- `_get_tech_stack()` — observations tech_stack lookup

**New API-specific helpers:**
- `_get_api_urls(target_id)` — query assets where `asset_value` contains `/api/`, `/v1/`, `/graphql`, `/swagger`, `/openapi`
- `_get_api_schemas(target_id)` — query `api_schemas` table for all discovered endpoints
- `_get_jwt_tokens(target_id)` — query `observations.headers` for `Authorization: Bearer` with 3 dot-separated base64 segments
- `_get_tech_filtered_urls(target_id, techs)` — assets joined with observations where `tech_stack` contains given technologies
- `_save_api_schema(...)` — upsert to `api_schemas` with duplicate handling
- `_get_oauth_urls(target_id)` — assets where path matches `/oauth/`, `/authorize/`, `/callback`, `/auth/`, `/login`

## Concurrency

Identical pattern to vuln_scanner: `WeightClass.HEAVY` (semaphore=2), `WeightClass.LIGHT` (semaphore=cpu_count). Env-configurable via `HEAVY_CONCURRENCY` / `LIGHT_CONCURRENCY`.

## Pipeline — 4-Stage Execution

```python
STAGES: list[Stage] = [
    Stage("api_discovery", [FfufApiTool, OpenapiParserTool, GraphqlIntrospectTool, TrufflehogTool]),
    Stage("auth_testing", [JwtTool, OauthTesterTool, CorsScannerTool]),
    Stage("injection_testing", [IdorTesterTool, MassAssignTesterTool, NosqlmapTool]),
    Stage("abuse_testing", [RateLimitTesterTool, GraphqlCopTool]),
]
```

Sequential stages, concurrent tools within each stage. Checkpointing via `JobState.current_phase` — resumes from last completed stage on restart.

### Stage 1: `api_discovery`

| Tool | Weight | Description |
|------|--------|-------------|
| FfufApiTool | HEAVY | Runs ffuf with API wordlists against discovered API roots. Cycles through GET/POST/PUT/DELETE with appropriate Content-Type headers. Writes found routes to `api_schemas`. |
| OpenapiParserTool | LIGHT | Fetches Swagger/OpenAPI specs from known paths (`/swagger.json`, `/openapi.yaml`, `/api-docs`). Parses every method+path+param. Bulk-inserts into `api_schemas`. Pure Python, no subprocess. |
| GraphqlIntrospectTool | LIGHT | Sends introspection query to GraphQL endpoints. Maps queries, mutations, types. Writes to `api_schemas` with `spec_type='graphql'`. Falls back to InQL if introspection is disabled. |
| TrufflehogTool | LIGHT | Runs `trufflehog filesystem` against downloaded API docs/specs for hardcoded keys. Found keys → immediate `vulnerabilities` + `alerts` (severity: critical). |

### Stage 2: `auth_testing`

| Tool | Weight | Description |
|------|--------|-------------|
| JwtTool | HEAVY | Detects JWT tokens from `observations.headers`. Tests: algorithm confusion (none, HS256↔RS256), key brute-force (rockyou-subset), claim tampering (sub, role, exp), JWK injection, kid path traversal. Wraps `jwt_tool.py` CLI. |
| OauthTesterTool | LIGHT | Pure httpx. Targets OAuth URLs. Tests: state parameter CSRF, redirect_uri bypass (path traversal, subdomain, scheme change), token leakage in referrer, scope escalation, PKCE downgrade. |
| CorsScannerTool | LIGHT | Wraps CORScanner binary. Tests all `/api/` URLs for: origin reflection, null origin trust, subdomain wildcard, credential leakage via `Access-Control-Allow-Credentials: true`. |

### Stage 3: `injection_testing`

| Tool | Weight | Description |
|------|--------|-------------|
| IdorTesterTool | HEAVY | Pure httpx. Reads `api_schemas` for path-parameterized endpoints. Iterates numeric IDs, UUIDs, slugs. Compares responses across two auth contexts (if available). Flags horizontal + vertical privilege escalation. Severity: high (horizontal), critical (vertical). |
| MassAssignTesterTool | LIGHT | Pure httpx. Reads write endpoints (POST/PUT/PATCH) from `api_schemas`. GETs current fields, replays each sensitive field (`role`, `is_admin`, `permissions`, `balance`, `verified`, `email_confirmed`, `active`, `plan`) as writable. GETs again to check if change stuck. Severity: critical (role/admin/permissions), high (others). |
| NosqlmapTool | HEAVY | Wraps nosqlmap binary. Targets API URLs where `tech_stack` shows MongoDB/CouchDB/Express/Node.js. Tests: `$gt`, `$ne`, `$regex` operator injection, auth bypass, data extraction. |

### Stage 4: `abuse_testing`

| Tool | Weight | Description |
|------|--------|-------------|
| RateLimitTesterTool | LIGHT | Pure httpx. Bursts N requests to sensitive endpoints (login/reset/otp/register/transfer/payment). Burst count from `target_profile.rate_limit_burst` (default 50). Measures response code/timing drift. Flags missing `429`/`Retry-After`. Severity: medium. Respects `oos_attacks` — skips if "No DoS" specified. |
| GraphqlCopTool | LIGHT | Wraps `graphql-cop` binary. Tests GraphQL endpoints from Stage 1 for: batching DoS potential, field suggestion leakage, introspection in prod, query depth/complexity limits. |

## Dockerfile — `docker/Dockerfile.api`

Multi-stage build:

```dockerfile
# Stage 1: Go builder (ffuf, trufflehog)
FROM golang:1.24-bookworm AS go-builder
RUN go install github.com/ffuf/ffuf/v2@latest

# Download trufflehog release binary
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_${ARCH}.tar.gz && \
    tar xzf trufflehog_linux_${ARCH}.tar.gz -C /usr/local/bin trufflehog

# Stage 2: Runtime
FROM python:3.10-slim-bookworm
```

**System packages:** `gcc libpq-dev git`

**Go binaries (from builder):** `ffuf`, `trufflehog`

**Git-cloned tools:**
- `jwt_tool` → `/opt/jwt_tool` (ticarpi/jwt_tool)
- `nosqlmap` → `/opt/nosqlmap` (codingo/NoSQLMap)
- `CORScanner` → `/opt/CORScanner` (chenjj/CORScanner)
- `graphql-cop` → `/opt/graphql-cop` (dolevf/graphql-cop)
- `InQL` → `/opt/inql` (doyensec/inql)

**Pip dependencies:** `httpx[http2]`, tool-specific requirements.txt files

**Wordlists:** SecLists API paths at `/app/wordlists/`

**Entrypoint:** `python -m workers.api_worker.main`

## main.py & Event Reporting

Identical pattern to vuln_scanner:
- `listen_queue("api_queue", "api_group", container_name, handle_message)`
- Loads Target, builds ScopeManager, ensures JobState row
- Runs Pipeline with heartbeat task (30s interval)
- On failure: `JobState.status = "FAILED"`

**Events pushed to Redis:**
- `stage_complete` — after each stage with aggregated stats
- `pipeline_complete` — when all 4 stages finish
- `critical_alert` — for severity >= high findings

**Vulnerability source_tool values:** `ffuf_api`, `openapi_parser`, `graphql_introspect`, `trufflehog`, `jwt_tool`, `oauth_tester`, `cors_scanner`, `idor_tester`, `mass_assign_tester`, `nosqlmap`, `rate_limit_tester`, `graphql_cop`

## Compliance

- **Custom headers:** Inject `Authorization: Bearer <token>` or API keys from `target_profile.custom_headers`
- **Rate limiting:** Respect PPS limits from `target_profile.rate_limit`
- **OOS attacks:** Check `target_profile.oos_attacks` — skip DoS-class tests (rate-limit bursting, GraphQL batching DoS) if "No DoS" specified
- **Scope:** All discovered URLs scope-checked via `ScopeManager` before testing
