# Phase 0 Design: Common Core & Library Setup (`lib_webbh`)

## Decisions

| Component | Decision |
|---|---|
| Schema | Full Phase 1 (10 tables) defined in `database.py` |
| DB Driver | Async-first (`asyncpg` + `AsyncEngine` + `AsyncSession`) |
| Messaging | Redis Streams (`XADD`/`XREADGROUP`) with consumer groups |
| Repo Layout | Monorepo with top-level service directories |
| Logger | stdlib `logging` with custom JSON formatter |
| Scope | `tldextract` + `netaddr` + `re`, returns `ScopeResult` dataclass |

---

## 1. Package Structure

```
WebAppBH/
├── shared/
│   └── lib_webbh/
│       ├── __init__.py          # Public API exports
│       ├── database.py          # AsyncEngine singleton, all OAM models
│       ├── scope.py             # ScopeManager (tldextract + netaddr + re)
│       ├── messaging.py         # Redis Streams wrapper
│       ├── logger.py            # JSON formatter on stdlib logging
│       └── setup.py             # Package metadata (pip install -e .)
│   └── setup_env.py             # Generates .env with API key + host IP
├── docker/
│   └── Dockerfile.base          # python:3.10-slim + lib_webbh installed
├── docs/plans/
└── docker-compose.yml           # Placeholder for Phase 1
```

---

## 2. `database.py` — Engine & Models

### Engine Singleton

- Module-level `_engine` / `_session_factory` initialized lazily via `get_engine()` and `get_session()`.
- Connection string: `postgresql+asyncpg://user:pass@host:5432/dbname`
- Pool config: `pool_size=10`, `max_overflow=20`, `pool_recycle=3600`
- Config read from env vars: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`.

### Base Model

All tables inherit a `TimestampMixin` with `created_at` and `updated_at` (server-side defaults, UTC).

### Schema (10 Tables)

| Table | Key Columns | Notes |
|---|---|---|
| `targets` | `id`, `company_name`, `base_domain`, `target_profile` (JSONB) | Profile holds wildcards, scope rules, rate limits, custom headers |
| `assets` | `id`, `target_id` (FK), `asset_type` (enum: subdomain/ip/cidr), `asset_value`, `source_tool` | Primary OAM asset table |
| `identities` | `id`, `target_id` (FK), `asn`, `organization`, `whois_data` (JSONB) | ASN/Whois enrichment |
| `locations` | `id`, `asset_id` (FK), `port`, `protocol`, `service`, `state` | Port/service mapping |
| `observations` | `id`, `asset_id` (FK), `tech_stack` (JSONB), `page_title`, `status_code`, `headers` (JSONB) | HTTP fingerprinting |
| `cloud_assets` | `id`, `target_id` (FK), `provider` (enum: aws/azure/gcp), `asset_type`, `url`, `is_public`, `findings` (JSONB) | Cloud resource tracking |
| `parameters` | `id`, `asset_id` (FK), `param_name`, `param_value`, `source_url` | Unique params for fuzzing |
| `vulnerabilities` | `id`, `target_id` (FK), `asset_id` (FK), `severity` (enum: critical/high/medium/low/info), `title`, `description`, `poc`, `source_tool` | Findings with PoC |
| `job_state` | `id`, `target_id` (FK), `container_name`, `current_phase`, `status` (enum: RUNNING/COMPLETED/QUEUED/FAILED), `last_seen`, `last_tool_executed` | Worker state tracking |
| `alerts` | `id`, `target_id` (FK), `vulnerability_id` (FK), `alert_type`, `message`, `is_read` | Real-time UI notifications |

### Relationships

- `target` → has many `assets`, `cloud_assets`, `vulnerabilities`, `job_state`, `alerts`
- `asset` → has many `locations`, `observations`, `parameters`, `vulnerabilities`
- `alert` → belongs to `vulnerability` (nullable FK)

---

## 3. `messaging.py` — Redis Streams Wrapper

### Connection

Lazy singleton `redis.asyncio.Redis` client, configured via `REDIS_HOST`, `REDIS_PORT` env vars.

### Public API

- **`push_task(queue: str, data: dict) -> str`** — `XADD` to named stream. Data serialized as JSON in a `payload` field. Returns message ID.

- **`listen_queue(queue: str, group: str, consumer: str, callback) -> None`** — Creates consumer group if needed (`XGROUP CREATE`, `MKSTREAM`). Loops on `XREADGROUP` with 5s block timeout. Deserializes payload, calls `await callback(message_id, data)`, then `XACK`.

- **`get_pending(queue: str, group: str) -> list`** — Returns unacknowledged messages via `XPENDING` for health-check and dead-letter inspection.

### Conventions

- Stream names per worker type: `recon_queue`, `fuzzing_queue`, `cloud_queue`, `api_queue`
- Consumer group per worker type, consumer name = container ID
- No dead-letter queue — orchestrator heartbeat (Phase 2) handles retries via `get_pending()`

### Message Format

```json
{
  "payload": "{\"target_id\": 1, \"asset_id\": 42, \"action\": \"scan_ports\"}",
  "timestamp": "2026-02-27T12:00:00Z"
}
```

---

## 4. `scope.py` — ScopeManager

### Initialization

Takes a `target_profile` dict (from `targets.target_profile` JSONB) and parses scope rules into three internal sets:

- **`_domain_rules`** — Wildcard domains like `*.example.com`. Stored as registered domain + wildcard flag. Normalized via `tldextract`.
- **`_network_rules`** — CIDRs and IPs parsed into `netaddr.IPNetwork` objects.
- **`_regex_rules`** — Compiled `re.Pattern` objects for custom regex strings.

### `ScopeResult` Dataclass

```python
@dataclass
class ScopeResult:
    in_scope: bool
    original: str           # Raw input as received
    normalized: str         # Clean domain/IP (no scheme, no path)
    asset_type: str         # "domain" | "ip" | "cidr"
    path: str | None        # "/api/v1/users?id=1" extracted from URL
```

### URL Normalization

1. Strip scheme (`https://`, `http://`)
2. Extract domain via `tldextract` → `sub.app.example.com`
3. Extract path → `/api/v1/users?id=1` — stored separately, linked back to domain
4. `normalized` = full subdomain + registered domain (no scheme, no path)

### Public API

- **`is_in_scope(item: str) -> ScopeResult | None`** — Accepts domain, URL, IP, or CIDR:
  1. Try parsing as IP/CIDR via `netaddr` → check `_network_rules`
  2. If URL-like, extract domain via `tldextract` → check `_domain_rules`
  3. Plain string → domain match first, then `_regex_rules` fallthrough
  4. Explicit out-of-scope exclusion always wins over inclusion

- **`add_rule(rule: str, in_scope: bool) -> None`** — Dynamically add a rule at runtime.

- **`get_scope_summary() -> dict`** — Serializable dict of all active rules for dashboard display.

---

## 5. `logger.py` — Structured JSON Logger

### Setup

`setup_logger(name: str, log_dir: str = "/app/shared/logs/") -> BoundLogger`

Returns a `logging.Logger` wrapped in a `BoundLogger` (via `LoggerAdapter`) with two handlers:

- **`StreamHandler`** → STDOUT (for `docker logs`)
- **`RotatingFileHandler`** → `/app/shared/logs/{name}.log` (10MB max, 5 backups)

### JSON Format

```json
{
  "timestamp": "2026-02-27T12:00:00.123Z",
  "level": "INFO",
  "logger": "recon-worker",
  "message": "Subdomain discovered",
  "container": "recon-core-01",
  "target_id": 1,
  "extra": {
    "asset_type": "subdomain",
    "asset": "api.example.com",
    "source_tool": "amass"
  }
}
```

### `asset_type` Values

| Value | Used When |
|---|---|
| `asn` | ASN discovery/enrichment |
| `ipv4` | IPv4 address found |
| `ipv6` | IPv6 address found |
| `cidr` | CIDR range identified |
| `domain` | Root/registered domain |
| `subdomain` | Subdomain enumeration |
| `open_port` | Port/service discovered |
| `endpoint` | URL path/route found |
| `param` | URL parameter extracted |
| `cloud_asset` | S3 bucket, Lambda, etc. |
| `vulnerability` | Finding logged |
| `job` | Worker state change |

### `bind()` Pattern

```python
log = setup_logger("recon-worker")
log = log.bind(target_id=1, asset_type="subdomain")
log.info("Discovered", extra={"asset": "api.example.com", "source_tool": "amass"})
```

- `container` auto-read from `HOSTNAME` env var
- `target_id` and `asset_type` injected via `bind()`
- `asset_type` can be overridden per-call in `extra`
- Timestamps always UTC ISO-8601
- Log level from `LOG_LEVEL` env var, defaults to `INFO`

---

## 6. `setup_env.py` — Auto-Configuration

Lives at `shared/setup_env.py`. On execution:

1. Generates `WEB_APP_BH_API_KEY` — `secrets.token_hex(32)` (64-char hex)
2. Detects host IP — `socket.gethostbyname(socket.gethostname())`, fallback `127.0.0.1`
3. Generates `DB_PASS` — `secrets.token_hex(16)` (32-char hex)
4. Writes `/app/shared/config/.env`:

```env
WEB_APP_BH_API_KEY=<64-char-hex>
HOST_IP=<detected-ip>
DB_HOST=postgres
DB_PORT=5432
DB_NAME=webbh
DB_USER=webbh_admin
DB_PASS=<32-char-hex>
REDIS_HOST=redis
REDIS_PORT=6379
```

- Idempotent: skips if `.env` already exists
- Prints API key to STDOUT on first run

---

## 7. `Dockerfile.base`

Lives at `docker/Dockerfile.base`:

```dockerfile
FROM python:3.10-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY shared/lib_webbh /app/shared/lib_webbh
RUN pip install --no-cache-dir -e /app/shared/lib_webbh
```

- `gcc` + `libpq-dev` required for `asyncpg` compilation on slim
- All worker/orchestrator Dockerfiles will `FROM webbh-base:latest`
- Editable install so shared volume mounts override at dev time

### Dependencies (in `setup.py`)

`sqlalchemy[asyncio]`, `asyncpg`, `redis[hiredis]`, `pydantic`, `netaddr`, `tldextract`

---

## 8. `__init__.py` — Public Exports

```python
# Database
from lib_webbh.database import get_engine, get_session
from lib_webbh.database import (
    Target, Asset, Identity, Location, Observation,
    CloudAsset, Parameter, Vulnerability, JobState, Alert
)

# Scope
from lib_webbh.scope import ScopeManager, ScopeResult

# Messaging
from lib_webbh.messaging import push_task, listen_queue, get_pending

# Logger
from lib_webbh.logger import setup_logger
```

### Usage Example

```python
from lib_webbh import get_session, Asset, ScopeManager, push_task, setup_logger

log = setup_logger("recon-worker").bind(target_id=1, asset_type="subdomain")

async with get_session() as session:
    asset = Asset(target_id=1, asset_type="subdomain", asset_value="api.example.com")
    session.add(asset)
    await session.commit()

await push_task("fuzzing_queue", {"target_id": 1, "asset_id": asset.id})
log.info("Queued for fuzzing", extra={"asset": "api.example.com"})
```
