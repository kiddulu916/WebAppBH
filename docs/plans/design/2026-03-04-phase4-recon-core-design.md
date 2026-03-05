# Phase 4 Design: Recon-Core Dockerized Worker

## Decisions

| Component | Decision |
|---|---|
| Database | Shared PostgreSQL via `lib_webbh` (no local SQLite) |
| Scope | Reuse `lib_webbh.ScopeManager` |
| Messaging | Long-lived Redis Stream consumer on `recon_queue` |
| Dockerfile | Multi-stage build (Go builder → Python builder → slim runtime) |
| Pipeline | 5 sequential stages with per-stage checkpointing via `job_state` |
| Concurrency | Dual semaphore pools: heavy (cap 2) and light (cap `cpu_count`) |
| Tool wrappers | Abstract `ReconTool` base class; subclasses implement `build_command()` + `parse_output()` |
| Results flow | Bulk assets to PostgreSQL; milestones + critical findings to Redis for SSE |

---

## 1. Architecture Overview

The Recon-Core worker is a long-lived Docker container that consumes jobs from the `recon_queue` Redis Stream and runs a 5-stage reconnaissance pipeline against targets.

### Integration with existing framework

- **Database**: Writes directly to PostgreSQL via `lib_webbh` (Asset, Location, Observation, Parameter, JobState, Alert models)
- **Messaging**: Consumes from `recon_queue` via `listen_queue()`, emits milestone events to `events:{target_id}` via `push_task()`
- **Scope**: Uses `lib_webbh.ScopeManager` initialized from the target's `target_profile` JSONB
- **Logging**: Uses `lib_webbh.setup_logger()` with bound `target_id` and `asset_type` context
- **Config**: Reads target-specific config from `/app/shared/config/{target_id}/` (written by orchestrator on `POST /targets`)

### Container lifecycle

1. Starts once, connects to PostgreSQL + Redis
2. Calls `listen_queue("recon_queue", "recon_group", container_id, callback)`
3. On receiving a message (`{"target_id": N, "action": "full_recon"}`), loads target profile, initializes `ScopeManager`, runs pipeline
4. Updates `job_state` throughout execution
5. Returns to listening when pipeline completes

---

## 2. Directory Structure

```
workers/recon-core/
├── Dockerfile
├── requirements.txt
├── main.py              # Entry point: Redis listener + pipeline orchestration
├── pipeline.py          # Stage definitions + execution order
├── base_tool.py         # ReconTool abstract base class
├── concurrency.py       # Semaphore pools (heavy/light)
├── tools/
│   ├── __init__.py
│   ├── subfinder.py
│   ├── assetfinder.py
│   ├── amass.py
│   ├── chaos.py
│   ├── sublist3r.py
│   ├── knockpy.py
│   ├── massdns.py
│   ├── httpx_tool.py
│   ├── naabu.py
│   ├── katana.py
│   ├── hakrawler.py
│   ├── waybackurls.py
│   ├── gauplus.py
│   └── paramspider.py
└── resolvers.txt        # DNS resolvers list for Massdns
```

---

## 3. Dockerfile (Multi-Stage)

### Stage 1 — Go builder

- Base: `golang:1.22-bookworm`
- `go install` for: Subfinder, Amass, Httpx, Naabu, Katana, Hakrawler, Gauplus, Chaos

### Stage 2 — Python builder

- Base: `python:3.10-slim-bookworm`
- `pip install` for: Sublist3r, Knockpy, Paramspider

### Stage 3 — Runtime

- Base: `python:3.10-slim-bookworm`
- Copies Go binaries from stage 1, Python packages from stage 2
- Installs `lib_webbh` from shared volume
- Installs minimal runtime deps: `massdns`, `libpcap-dev` (for Naabu)
- Copies worker source from `workers/recon-core/`
- Entry point: `python -m main`

---

## 4. ReconTool Base Class

```python
class WeightClass(Enum):
    HEAVY = "heavy"    # Amass, Katana, Naabu
    LIGHT = "light"    # Subfinder, Assetfinder, Httpx, etc.

class ReconTool(ABC):
    name: str
    weight_class: WeightClass

    async def execute(self, target, scope_manager, session, headers=None):
        # 1. Check 24-hour cooldown via job_state
        # 2. Acquire semaphore for weight class
        # 3. Build CLI command (inject custom headers if supported)
        # 4. Run subprocess with timeout
        # 5. Parse output → list of raw results
        # 6. Scope-check each result via scope_manager.is_in_scope()
        # 7. Deduplicate against existing DB assets
        # 8. Bulk insert new assets to PostgreSQL
        # 9. Log stats (found, in-scope, new, duplicates)
        # 10. Update job_state.last_tool_executed

    @abstractmethod
    def build_command(self, target, headers) -> list[str]: ...

    @abstractmethod
    def parse_output(self, stdout: str) -> list[str]: ...
```

The `execute()` method handles all common plumbing. Subclasses only implement `build_command()` and `parse_output()`.

### Output type routing

The base class `execute()` checks the return type from `parse_output()`:
- Plain strings → `Asset` inserts (subdomains, IPs, endpoints)
- Dicts with `port` key → `Location` inserts
- Dicts with `param_name` key → `Parameter` inserts

---

## 5. Concurrency Model

```python
# concurrency.py
heavy_sem = asyncio.BoundedSemaphore(2)
light_sem = asyncio.BoundedSemaphore(os.cpu_count())
```

- **Heavy pool** (cap 2): Amass, Katana, Naabu — memory-intensive tools that risk OOM
- **Light pool** (cap `cpu_count`): Subfinder, Assetfinder, Httpx, and all others

The base class `execute()` acquires the correct semaphore based on `self.weight_class` before spawning the subprocess, releases in a `finally` block.

---

## 6. Pipeline Stages

```python
STAGES = [
    Stage("passive_discovery", [Subfinder, Assetfinder, Chaos, AmassPassive]),
    Stage("active_discovery",  [Sublist3r, Knockpy, AmassActive]),
    Stage("liveness_dns",      [Massdns, Httpx]),
    Stage("port_mapping",      [Naabu]),
    Stage("deep_recon",        [Katana, Hakrawler, Waybackurls, Gauplus, Paramspider]),
]
```

### Stage execution rules

1. **Passive Discovery** — All 4 tools run concurrently (light-weight except Amass which claims a heavy slot). Results merged and deduplicated. Each unique subdomain/IP inserted as an `Asset` row.

2. **Active Discovery** — Runs against the base domain. Results merged with stage 1 findings, only net-new assets inserted.

3. **Liveness & DNS** — Takes all assets from stages 1+2. Massdns resolves DNS first, then Httpx probes for live HTTP services. Assets that don't resolve are marked but kept. Live assets get an `Observation` row (status_code, page_title, tech_stack).

4. **Port Mapping** — Naabu runs only against IPs that resolved in stage 3. Each open port inserted as a `Location` row linked to the asset.

5. **Deep Recon** — Runs only against assets with live HTTP services (status_code 200-399 from stage 3). Katana/Hakrawler crawl for endpoints, Waybackurls/Gauplus pull historical URLs, Paramspider extracts parameters. Results go to `Asset` (endpoints), `Parameter` (params), and `Observation` (additional findings).

### Data flow between stages

Later stages query the DB for assets inserted by earlier stages rather than passing in-memory lists. This ensures resumability — if the worker restarts mid-pipeline, stage 3 can still find stage 1+2 results in PostgreSQL.

### Stage transitions

Each stage writes `job_state.current_phase` on start. On restart, the pipeline queries `job_state` and skips completed stages.

---

## 7. Cooldown, Heartbeat & Alerting

### 24-hour cooldown

Before each tool runs against a target, `execute()` queries `job_state` for a matching `(target_id, container_name)` entry with `last_seen` within the past 24 hours. If found and status is `COMPLETED`, the tool is skipped. Cooldown is per-target — if fully scanned 12 hours ago, the entire pipeline skips. Partial scans resume via stage checkpointing.

### Heartbeat

A background `asyncio.Task` runs alongside the pipeline, updating `job_state` every 30 seconds:

```python
async def heartbeat_loop(target_id, session):
    while running:
        await update_job_state(session, target_id, {
            "status": "RUNNING",
            "last_seen": utcnow(),
            "current_phase": current_stage.name,
            "last_tool_executed": current_tool.name,
        })
        await asyncio.sleep(30)
```

The orchestrator's existing zombie detection (`ZOMBIE_TIMEOUT=600s`) catches workers that stop sending heartbeats.

### Critical alerts

After each tool's results are processed, a detector scans for high-value findings:

- Exposed `.git`, `.env`, `.DS_Store`, `wp-config.php` paths
- Ports 3389 (RDP), 5900 (VNC), 27017 (MongoDB), 9200 (Elasticsearch) open
- Status codes 403 on admin paths (potential bypass targets)

Matches are written to the `alerts` table with `alert_type="critical"` and pushed to Redis (`events:{target_id}`) for immediate SSE delivery to the dashboard.

---

## 8. Tool Wrapper Examples

### Light tool — Subfinder

```python
class Subfinder(ReconTool):
    name = "subfinder"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, headers=None):
        return ["subfinder", "-d", target.base_domain, "-silent", "-json"]

    def parse_output(self, stdout):
        return [json.loads(line)["host"] for line in stdout.strip().splitlines() if line]
```

### Heavy tool — Naabu

```python
class Naabu(ReconTool):
    name = "naabu"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, headers=None):
        return ["naabu", "-list", self.input_file, "-json", "-top-ports", "1000"]

    def parse_output(self, stdout):
        return [json.loads(line) for line in stdout.strip().splitlines() if line]
```

Naabu takes a file of IPs as input (written by the base class from stage 3 results) and returns structured dicts for `Location` row inserts.

---

## 9. Message Contract

### Inbound (from orchestrator via `recon_queue`)

```json
{"target_id": 1, "action": "full_recon"}
```

### Outbound events (to `events:{target_id}`)

```json
{"event": "stage_complete", "stage": "passive_discovery", "stats": {"found": 142, "in_scope": 138, "new": 95}}
{"event": "critical_alert", "alert_id": 7, "message": "Exposed .git directory at sub.example.com/.git"}
{"event": "pipeline_complete", "target_id": 1, "duration_seconds": 1834}
```

---

## 10. Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME` | From `.env` | PostgreSQL connection |
| `REDIS_HOST`, `REDIS_PORT` | From `.env` | Redis connection |
| `HEAVY_CONCURRENCY` | `2` | Max concurrent heavy tools |
| `LIGHT_CONCURRENCY` | `cpu_count()` | Max concurrent light tools |
| `TOOL_TIMEOUT` | `600` | Default subprocess timeout (seconds) |
| `COOLDOWN_HOURS` | `24` | Hours before re-scanning a target |
| `HEARTBEAT_INTERVAL` | `30` | Seconds between heartbeat updates |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
