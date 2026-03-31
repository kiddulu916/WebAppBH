# WSTG-Aligned Restructure — 08 Target Expansion & Resource Management

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview, restructure-03-info-gathering
**Scope:** TargetExpander, Priority Queue, Resource Guard

---

## Overview

When info_gathering completes for a seed target, it produces an inventory of subdomains, virtual hosts, and live URLs. Each of these represents a distinct attack surface that must run through the full WSTG pipeline. The TargetExpander creates child target records and enqueues them into a prioritized queue. The Resource Guard prevents the system from overwhelming itself.

---

## TargetExpander

### Purpose

The TargetExpander is a post-processing step that fires after info_gathering completes for any target. It reads all Asset records produced by the info_gathering worker and creates child Target records for each unique host that warrants independent testing.

### Trigger

The event engine fires `expand_targets` when `info_gathering` status changes to `complete` for a given target.

### Logic

```python
# orchestrator/target_expander.py

class TargetExpander:
    """Creates child targets from info_gathering results.

    Reads Asset records (subdomains, vhosts) and creates child Target
    records that each run through the full WSTG pipeline independently.
    """

    async def expand(self, parent_target_id: int):
        """Main expansion logic.

        1. Read all Asset records for the parent target
        2. Deduplicate by resolved IP + hostname
        3. Score priority for each child
        4. Create child Target records
        5. Enqueue each child to its first worker queue
        """
        async with get_session() as session:
            # Get all subdomains and vhosts discovered
            assets = await session.execute(
                select(Asset)
                .where(Asset.target_id == parent_target_id)
                .where(Asset.asset_type.in_(["subdomain", "vhost", "live_url"]))
            )
            assets = assets.scalars().all()

            parent = await session.get(Target, parent_target_id)

            # Deduplicate: group by (hostname, resolved_ip)
            unique_hosts = self._deduplicate(assets)

            for host_info in unique_hosts:
                # Skip the parent domain itself
                if host_info["hostname"] == parent.domain:
                    continue

                # Check scope
                scope_result = ScopeManager(parent.scope_config).check(
                    host_info["hostname"]
                )
                if not scope_result.in_scope:
                    continue

                priority = self._score_priority(host_info, parent)

                child = Target(
                    domain=host_info["hostname"],
                    parent_target_id=parent_target_id,
                    campaign_id=parent.campaign_id,
                    scope_config=parent.scope_config,
                    priority=priority,
                    target_type="child",
                    status="pending"
                )
                session.add(child)
                await session.flush()  # Get the child.id

                # Copy credential config from parent
                self._copy_credentials(parent_target_id, child.id)

            await session.commit()

            # Enqueue all children to config_mgmt (first post-info_gathering worker)
            children = await session.execute(
                select(Target)
                .where(Target.parent_target_id == parent_target_id)
                .where(Target.status == "pending")
            )
            for child in children.scalars().all():
                await push_task(
                    "config_mgmt_queue",
                    {
                        "target_id": child.id,
                        "priority": child.priority,
                        "parent_target_id": parent_target_id
                    }
                )
```

### Deduplication Rules

Multiple tools may discover the same host. Deduplication prevents redundant testing:

1. **Exact hostname match** — `api.target.com` from Subfinder and `api.target.com` from Assetfinder are the same host
2. **IP-based dedup** — If `cdn1.target.com` and `cdn2.target.com` resolve to the same IP AND return the same response (same content-length, same title), they are treated as a single target with aliases
3. **Wildcard detection** — If 50+ subdomains resolve to the same IP with identical responses, it's a DNS wildcard. Create one child target and mark it `wildcard=True`

```python
def _deduplicate(self, assets):
    """Group assets into unique testable hosts."""
    by_hostname = {}
    for asset in assets:
        hostname = asset.data.get("hostname", "").lower().strip(".")
        if not hostname:
            continue
        if hostname not in by_hostname:
            by_hostname[hostname] = {
                "hostname": hostname,
                "ips": set(),
                "sources": [],
                "asset_type": asset.asset_type,
            }
        if asset.data.get("ip"):
            by_hostname[hostname]["ips"].add(asset.data["ip"])
        by_hostname[hostname]["sources"].append(asset.source_tool)

    # Detect wildcards: many hostnames resolving to same IP with same response
    ip_groups = defaultdict(list)
    for info in by_hostname.values():
        for ip in info["ips"]:
            ip_groups[ip].append(info)

    for ip, hosts in ip_groups.items():
        if len(hosts) > 50:
            # Wildcard detected — keep only the first host, mark as wildcard
            for host in hosts[1:]:
                host["skip"] = True
            hosts[0]["wildcard"] = True
            hosts[0]["wildcard_count"] = len(hosts)

    return [h for h in by_hostname.values() if not h.get("skip")]
```

### Credential Propagation

Child targets inherit credentials from their parent. The TargetExpander copies the parent's `shared/config/{parent_id}/credentials.json` to `shared/config/{child_id}/credentials.json`. This ensures all child targets can use the same Tester session and Testing User configuration.

```python
def _copy_credentials(self, parent_id, child_id):
    """Copy credential config from parent to child target."""
    parent_creds = Path(f"shared/config/{parent_id}/credentials.json")
    child_dir = Path(f"shared/config/{child_id}")
    child_dir.mkdir(parents=True, exist_ok=True)

    if parent_creds.exists():
        shutil.copy2(parent_creds, child_dir / "credentials.json")
        os.chmod(child_dir / "credentials.json", 0o600)
```

---

## Priority Scoring

Not all child targets are equally important. Priority scoring determines the order in which child targets are processed.

### Scoring Algorithm

```python
def _score_priority(self, host_info, parent):
    """Calculate priority score for a child target.

    Higher score = higher priority = processed first.

    Score range: 0-100
    """
    score = 50  # Base score

    # Seed targets always get maximum priority
    if host_info.get("is_seed"):
        return 100

    # Unique IP gets priority over shared-IP hosts
    if len(host_info["ips"]) == 1:
        ip = list(host_info["ips"])[0]
        # Check how many other hosts share this IP
        shared_count = self._count_hosts_on_ip(ip)
        if shared_count == 1:
            score += 20  # Dedicated IP — likely important
        elif shared_count <= 5:
            score += 10  # Small shared hosting
        else:
            score -= 10  # Large shared hosting / CDN

    # Hostname indicators
    hostname = host_info["hostname"]
    high_value_prefixes = [
        "api", "admin", "portal", "app", "dashboard",
        "login", "auth", "sso", "internal", "staging",
        "dev", "test", "uat", "preprod"
    ]
    for prefix in high_value_prefixes:
        if hostname.startswith(f"{prefix}."):
            score += 15
            break

    low_value_prefixes = [
        "cdn", "static", "assets", "img", "images",
        "media", "fonts", "css", "js"
    ]
    for prefix in low_value_prefixes:
        if hostname.startswith(f"{prefix}."):
            score -= 15
            break

    # Multiple discovery sources = likely real, not stale
    source_count = len(set(host_info.get("sources", [])))
    if source_count >= 3:
        score += 10
    elif source_count == 1:
        score -= 5

    # Wildcard hosts get lowest priority
    if host_info.get("wildcard"):
        score -= 30

    return max(0, min(100, score))
```

### Priority Tiers

| Score Range | Tier | Examples |
|-------------|------|----------|
| 90-100 | Critical | Seed targets, admin/portal subdomains on dedicated IPs |
| 70-89 | High | API subdomains, staging/dev environments, auth endpoints |
| 50-69 | Normal | Standard subdomains with unique content |
| 30-49 | Low | Shared-IP subdomains, single-source discoveries |
| 0-29 | Background | CDN/static subdomains, wildcard hosts |

### Queue Ordering

Redis Streams don't natively support priority. Instead, the orchestrator uses **multiple queues per worker** with weighted consumption:

```python
# Priority queue implementation

PRIORITY_QUEUES = {
    "config_mgmt_queue:critical": {"min_score": 90, "weight": 5},
    "config_mgmt_queue:high":     {"min_score": 70, "weight": 3},
    "config_mgmt_queue:normal":   {"min_score": 50, "weight": 2},
    "config_mgmt_queue:low":      {"min_score": 0,  "weight": 1},
}
```

Workers consume from higher-priority queues first. The weight determines how many messages to read from each queue per cycle:

```python
async def listen_priority_queues(queue_prefix, consumer_group, consumer_name):
    """Read from priority queues with weighted consumption.

    In each cycle:
    - Read up to 5 messages from :critical
    - Read up to 3 messages from :high
    - Read up to 2 messages from :normal
    - Read up to 1 message from :low

    This ensures critical targets are processed first while still
    making progress on lower-priority targets.
    """
    queues = [
        (f"{queue_prefix}:critical", 5),
        (f"{queue_prefix}:high", 3),
        (f"{queue_prefix}:normal", 2),
        (f"{queue_prefix}:low", 1),
    ]

    while True:
        for queue_name, batch_size in queues:
            messages = await read_stream(
                queue_name, consumer_group, consumer_name,
                count=batch_size, block=100  # Short block to cycle through queues
            )
            for msg in messages:
                yield msg
```

---

## Resource Guard

### Problem

A campaign against a large organization may discover 500+ subdomains. If all 500 are enqueued immediately, the system could:
- Exhaust Docker container memory/CPU
- Saturate outbound network bandwidth (triggering target-side rate limiting or WAF blocks)
- Make the dashboard unresponsive due to database query load
- Overwhelm Redis with thousands of pending stream messages

### Solution: Tiered Resource Guard

The Resource Guard monitors system resources and throttles target processing based on current load.

### Tiers

| Tier | CPU Threshold | Memory Threshold | Active Workers | Action |
|------|--------------|-------------------|----------------|--------|
| Green | < 60% | < 60% | < 8 | Full speed — process all queues normally |
| Yellow | 60-80% | 60-80% | 8-12 | Reduced — skip `low` priority queue, reduce batch sizes by 50% |
| Red | 80-90% | 80-90% | 12-16 | Throttled — only `critical` and `high` queues, batch size 1, 5-second delay between batches |
| Critical | > 90% | > 90% | > 16 | Paused — stop processing new targets, only allow in-progress pipelines to complete |

### Implementation

```python
# orchestrator/resource_guard.py

class ResourceGuard:
    """Monitors system resources and controls processing throughput.

    Runs as an async background task in the orchestrator.
    Workers query the guard before pulling new work.
    """

    # Default thresholds — configurable via environment variables
    THRESHOLDS = {
        "green":    {"cpu": 60,  "memory": 60,  "workers": 8},
        "yellow":   {"cpu": 80,  "memory": 80,  "workers": 12},
        "red":      {"cpu": 90,  "memory": 90,  "workers": 16},
    }

    def __init__(self):
        self._current_tier = "green"
        self._override = None  # Manual override from dashboard

    async def get_current_tier(self):
        """Determine current resource tier."""
        if self._override:
            return self._override

        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        active_workers = await self._count_active_workers()

        if (cpu > self.THRESHOLDS["red"]["cpu"] or
            memory > self.THRESHOLDS["red"]["memory"] or
            active_workers > self.THRESHOLDS["red"]["workers"]):
            return "critical"
        elif (cpu > self.THRESHOLDS["yellow"]["cpu"] or
              memory > self.THRESHOLDS["yellow"]["memory"] or
              active_workers > self.THRESHOLDS["yellow"]["workers"]):
            return "red"
        elif (cpu > self.THRESHOLDS["green"]["cpu"] or
              memory > self.THRESHOLDS["green"]["memory"] or
              active_workers > self.THRESHOLDS["green"]["workers"]):
            return "yellow"
        else:
            return "green"

    def get_batch_config(self, tier):
        """Return queue consumption config for the given tier."""
        configs = {
            "green": {
                "queues": ["critical", "high", "normal", "low"],
                "batch_multiplier": 1.0,
                "delay_seconds": 0,
            },
            "yellow": {
                "queues": ["critical", "high", "normal"],
                "batch_multiplier": 0.5,
                "delay_seconds": 1,
            },
            "red": {
                "queues": ["critical", "high"],
                "batch_multiplier": 0.25,
                "delay_seconds": 5,
            },
            "critical": {
                "queues": [],  # No new work
                "batch_multiplier": 0,
                "delay_seconds": 10,
            },
        }
        return configs[tier]

    async def _count_active_workers(self):
        """Count currently running worker containers."""
        async with get_session() as session:
            result = await session.execute(
                select(func.count(JobState.id))
                .where(JobState.status == "running")
            )
            return result.scalar() or 0
```

### Reserved Resources

The orchestrator and dashboard always have reserved resources that cannot be consumed by workers:

```yaml
# docker-compose.yml resource reservations

services:
  orchestrator:
    deploy:
      resources:
        reservations:
          cpus: "0.5"
          memory: 512M

  dashboard:
    deploy:
      resources:
        reservations:
          cpus: "0.5"
          memory: 512M

  postgres:
    deploy:
      resources:
        reservations:
          cpus: "0.25"
          memory: 256M

  redis:
    deploy:
      resources:
        reservations:
          cpus: "0.25"
          memory: 256M
```

Workers have limits but no reservations — they use whatever is available:

```yaml
  worker_info_gathering:
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 2G
```

### Dashboard Resource Guard API

The orchestrator exposes a resource guard API for the dashboard:

```
GET  /api/v1/resources/status     — Current tier, CPU/memory/worker counts
POST /api/v1/resources/override   — Manual tier override (admin only)
GET  /api/v1/resources/thresholds — Current threshold configuration
PUT  /api/v1/resources/thresholds — Update thresholds
```

The dashboard displays the current resource tier with a color-coded indicator and allows administrators to:
- View real-time CPU, memory, and active worker counts
- Override the automatic tier (e.g., force "red" during a presentation)
- Adjust threshold values without restarting the orchestrator

### Environment Variable Overrides

```bash
# Resource guard thresholds (defaults shown)
RESOURCE_GUARD_CPU_GREEN=60
RESOURCE_GUARD_CPU_YELLOW=80
RESOURCE_GUARD_CPU_RED=90
RESOURCE_GUARD_MEM_GREEN=60
RESOURCE_GUARD_MEM_YELLOW=80
RESOURCE_GUARD_MEM_RED=90
RESOURCE_GUARD_WORKERS_GREEN=8
RESOURCE_GUARD_WORKERS_YELLOW=12
RESOURCE_GUARD_WORKERS_RED=16
```

---

## Target Lifecycle

```
Seed Target created (campaign creation)
    |
    v
info_gathering runs against seed target
    |
    v
info_gathering completes
    |
    v
TargetExpander fires
    |
    +--> Reads Asset records (subdomains, vhosts)
    +--> Deduplicates by hostname + IP
    +--> Scores priority for each child
    +--> Creates child Target records
    +--> Enqueues children to priority queues
    |
    v
Resource Guard checks tier
    |
    +--> Green: all queues processed
    +--> Yellow: low priority deferred
    +--> Red: only critical/high processed
    +--> Critical: no new processing
    |
    v
Workers pick up child targets by priority
    |
    v
Each child target runs through remaining WSTG pipeline:
  config_mgmt -> identity_mgmt -> authentication ->
  authorization + session_mgmt (parallel) ->
  input_validation -> error_handling + cryptography (parallel) ->
  business_logic + client_side (parallel) ->
  chain_worker -> reporting
```

### Child Target Status Tracking

Each child target has its own `JobState` records. The parent target's dashboard view shows:
- Total children discovered
- Children completed / in-progress / pending / skipped
- Aggregate vulnerability counts across all children
- Per-child drill-down

```python
# Target model additions

class Target(Base):
    __tablename__ = "targets"

    # ... existing fields ...

    parent_target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    target_type = Column(String, default="seed")  # "seed" or "child"
    priority = Column(Integer, default=50)
    wildcard = Column(Boolean, default=False)
    wildcard_count = Column(Integer, nullable=True)

    # Relationship
    parent = relationship("Target", remote_side="Target.id", back_populates="children")
    children = relationship("Target", back_populates="parent")
```

---

## Scale Projections

| Campaign Size | Subdomains | Child Targets (after dedup) | Estimated Pipeline Duration |
|--------------|------------|----------------------------|---------------------------|
| Small | 10-50 | 5-30 | 2-6 hours |
| Medium | 50-200 | 30-120 | 6-24 hours |
| Large | 200-1000 | 100-500 | 1-5 days |
| Enterprise | 1000+ | 500+ | 5+ days (with throttling) |

The Resource Guard ensures that even Enterprise-scale campaigns don't crash the system — they just take longer to complete as resources are throttled.
