# WSTG-Aligned Restructure — 10 Database & Messaging Changes

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview
**Scope:** Schema changes, new tables, Redis streams, migration

---

## Overview

The restructured framework requires changes to the database schema and Redis messaging layer to support:
- New worker types and their tracking
- Target hierarchy (seed → child)
- WSTG section tracking on vulnerability records
- Escalation context for chain worker integration
- Priority queues for target expansion

---

## Database Schema Changes

### Modified Tables

#### Target

```python
class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    domain = Column(String, nullable=False)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)
    status = Column(String, default="pending")
    scope_config = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # NEW: Target hierarchy
    parent_target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    target_type = Column(String, default="seed")  # "seed" or "child"
    priority = Column(Integer, default=50)         # 0-100 priority score
    wildcard = Column(Boolean, default=False)
    wildcard_count = Column(Integer, nullable=True)

    # Relationships
    parent = relationship("Target", remote_side=[id], back_populates="children")
    children = relationship("Target", back_populates="parent")
    vulnerabilities = relationship("Vulnerability", back_populates="target")
    assets = relationship("Asset", back_populates="target")
    observations = relationship("Observation", back_populates="target")
```

#### Vulnerability

```python
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    # Identification
    vuln_type = Column(String, nullable=False)        # e.g., "sqli", "xss_reflected", "cors_misconfiguration"
    section_id = Column(String, nullable=True)         # e.g., "4.7.5", "4.11.7" — WSTG section reference
    worker_type = Column(String, nullable=True)        # e.g., "input_validation", "client_side"
    stage_name = Column(String, nullable=True)         # e.g., "sql_injection", "cors_testing"
    source_tool = Column(String, nullable=True)        # e.g., "SqlmapTool", "CorsTester"

    # Classification
    severity = Column(String, nullable=False)          # "critical", "high", "medium", "low", "info"
    confirmed = Column(Boolean, default=False)         # True if exploit verified
    false_positive = Column(Boolean, default=False)    # Manually marked by user

    # Details
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)              # Tool-specific structured data
    evidence = Column(JSON, nullable=True)             # Request/response pairs, screenshots
    remediation = Column(Text, nullable=True)

    # Metadata
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    target = relationship("Target", back_populates="vulnerabilities")
    asset = relationship("Asset")
    escalation_contexts = relationship("EscalationContext", back_populates="vulnerability")
```

#### JobState

```python
class JobState(Base):
    __tablename__ = "job_state"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    worker_type = Column(String, nullable=False)        # e.g., "info_gathering", "config_mgmt"
    status = Column(String, default="pending")           # "pending", "queued", "running", "complete", "failed"

    # Pipeline progress
    current_stage_index = Column(Integer, default=0)
    current_section_id = Column(String, nullable=True)  # e.g., "4.1.3" — current stage's WSTG section
    last_tool_executed = Column(String, nullable=True)

    # Skip tracking
    skipped = Column(Boolean, default=False)
    skip_reason = Column(String, nullable=True)

    # Timing
    queued_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Error tracking
    error = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
```

### New Tables

#### Campaign

```python
class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="pending")     # "pending", "running", "paused", "complete", "cancelled"

    # Configuration
    scope_config = Column(JSON, nullable=True)      # Default scope for all targets
    rate_limit = Column(Integer, default=50)         # Requests per second
    has_credentials = Column(Boolean, default=False)

    # Timing
    created_at = Column(DateTime, default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    targets = relationship("Target", back_populates="campaign")
```

#### EscalationContext

```python
class EscalationContext(Base):
    __tablename__ = "escalation_contexts"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)

    # Access details
    access_type = Column(String, nullable=False)      # "user_account", "admin_panel", "internal_endpoint"
    access_method = Column(Text, nullable=False)       # Full attack chain description
    session_data = Column(Text, nullable=True)         # Encrypted session token/cookie
    data_exposed = Column(Text, nullable=True)         # Description of visible data
    severity = Column(String, nullable=False)

    # WSTG tracking
    section_id = Column(String, nullable=True)

    # Chain worker consumption
    consumed_by_chain = Column(Boolean, default=False)
    chain_findings = Column(JSON, nullable=True)       # Results from chain worker probing

    # Metadata
    created_at = Column(DateTime, default=func.now())

    # Relationships
    target = relationship("Target")
    vulnerability = relationship("Vulnerability", back_populates="escalation_contexts")
```

#### ChainFinding

```python
class ChainFinding(Base):
    __tablename__ = "chain_findings"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    escalation_context_id = Column(Integer, ForeignKey("escalation_contexts.id"), nullable=False)

    # Chain details
    chain_description = Column(Text, nullable=False)    # Step-by-step chain
    entry_vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    linked_vulnerability_ids = Column(JSON, nullable=True)  # List of vuln IDs in the chain
    total_impact = Column(Text, nullable=True)          # Combined impact assessment
    severity = Column(String, nullable=False)           # Overall chain severity

    # Metadata
    created_at = Column(DateTime, default=func.now())

    # Relationships
    target = relationship("Target")
    escalation_context = relationship("EscalationContext")
    entry_vulnerability = relationship("Vulnerability", foreign_keys=[entry_vulnerability_id])
```

---

## Indexes

```python
# Performance indexes for common query patterns

Index("ix_targets_parent", Target.parent_target_id)
Index("ix_targets_campaign", Target.campaign_id)
Index("ix_targets_status", Target.status)
Index("ix_targets_priority", Target.priority)

Index("ix_vulnerabilities_target", Vulnerability.target_id)
Index("ix_vulnerabilities_section", Vulnerability.section_id)
Index("ix_vulnerabilities_severity", Vulnerability.severity)
Index("ix_vulnerabilities_worker", Vulnerability.worker_type)
Index("ix_vulnerabilities_confirmed", Vulnerability.confirmed)

Index("ix_job_state_target", JobState.target_id)
Index("ix_job_state_worker", JobState.worker_type)
Index("ix_job_state_status", JobState.status)
Index("ix_job_state_target_worker", JobState.target_id, JobState.worker_type)

Index("ix_assets_target", Asset.target_id)
Index("ix_assets_type", Asset.asset_type)

Index("ix_observations_target", Observation.target_id)
Index("ix_observations_type", Observation.observation_type)

Index("ix_escalation_target", EscalationContext.target_id)
Index("ix_escalation_consumed", EscalationContext.consumed_by_chain)

Index("ix_campaign_status", Campaign.status)
```

---

## Redis Messaging Changes

### Stream Names

The restructured framework uses priority-tiered streams for each worker:

```python
# Old stream names (current)
STREAMS = [
    "recon_queue",
    "fuzzing_queue",
    "cloud_queue",
    "api_queue",
]

# New stream names (restructured)
WORKER_QUEUES = {
    "info_gathering":   "info_gathering_queue",
    "config_mgmt":      "config_mgmt_queue",
    "identity_mgmt":    "identity_mgmt_queue",
    "authentication":   "authentication_queue",
    "authorization":    "authorization_queue",
    "session_mgmt":     "session_mgmt_queue",
    "input_validation": "input_validation_queue",
    "error_handling":   "error_handling_queue",
    "cryptography":     "cryptography_queue",
    "business_logic":   "business_logic_queue",
    "client_side":      "client_side_queue",
    "chain_worker":     "chain_worker_queue",
    "reporting":        "reporting_queue",
}

# Each queue has four priority tiers
PRIORITY_TIERS = ["critical", "high", "normal", "low"]

# Full stream list:
# info_gathering_queue:critical, info_gathering_queue:high, ...
# config_mgmt_queue:critical, config_mgmt_queue:high, ...
# etc.
```

### Consumer Groups

Each worker type creates its own consumer group:

```python
# Consumer group pattern
GROUP_NAME = f"{worker_type}_group"
CONSUMER_NAME = f"{worker_type}_{hostname}"

# Example:
# Group: "info_gathering_group"
# Consumer: "info_gathering_worker-abc123"
```

### Event Streams

Target-specific event streams remain unchanged:

```python
# SSE event stream — one per target
EVENT_STREAM = f"events:{target_id}"

# Message format
{
    "event": "worker_complete",    # Event type
    "worker": "config_mgmt",      # Worker that completed
    "target_id": 42,              # Target ID
    "timestamp": "2026-03-29T...",
    "data": {}                    # Event-specific payload
}
```

### Messaging Helpers

Updated `lib_webbh/messaging.py` with priority queue support:

```python
# lib_webbh/messaging.py additions

async def push_priority_task(queue_prefix, data, priority_score):
    """Push a task to the appropriate priority tier.

    Args:
        queue_prefix: Base queue name (e.g., "config_mgmt_queue")
        data: Task payload
        priority_score: 0-100 priority score
    """
    if priority_score >= 90:
        tier = "critical"
    elif priority_score >= 70:
        tier = "high"
    elif priority_score >= 50:
        tier = "normal"
    else:
        tier = "low"

    stream_name = f"{queue_prefix}:{tier}"
    await push_task(stream_name, data)


async def listen_priority_queues(queue_prefix, group, consumer, resource_guard=None):
    """Read from priority-tiered queues with weighted consumption.

    Yields messages in priority order. Higher priority tiers
    are read more frequently.
    """
    tier_config = [
        ("critical", 5),   # Read up to 5 messages per cycle
        ("high",     3),
        ("normal",   2),
        ("low",      1),
    ]

    while True:
        # Check resource guard for allowed tiers
        if resource_guard:
            tier = await resource_guard.get_current_tier()
            batch_config = resource_guard.get_batch_config(tier)
            allowed_tiers = set(batch_config["queues"])
            delay = batch_config["delay_seconds"]
        else:
            allowed_tiers = {"critical", "high", "normal", "low"}
            delay = 0

        yielded_any = False

        for tier_name, batch_size in tier_config:
            if tier_name not in allowed_tiers:
                continue

            stream_name = f"{queue_prefix}:{tier_name}"
            messages = await read_stream(
                stream_name, group, consumer,
                count=batch_size, block=100
            )

            for msg in messages:
                yielded_any = True
                yield msg

        if not yielded_any:
            await asyncio.sleep(1)  # No messages — back off

        if delay > 0:
            await asyncio.sleep(delay)
```

---

## Migration Strategy

### Alembic Migration

The schema changes are applied via Alembic migrations:

```python
# alembic/versions/xxxx_wstg_restructure.py

def upgrade():
    # 1. Add new columns to targets
    op.add_column("targets", sa.Column("parent_target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=True))
    op.add_column("targets", sa.Column("target_type", sa.String, server_default="seed"))
    op.add_column("targets", sa.Column("priority", sa.Integer, server_default="50"))
    op.add_column("targets", sa.Column("wildcard", sa.Boolean, server_default="false"))
    op.add_column("targets", sa.Column("wildcard_count", sa.Integer, nullable=True))
    op.add_column("targets", sa.Column("campaign_id", sa.Integer, sa.ForeignKey("campaigns.id"), nullable=True))

    # 2. Add new columns to vulnerabilities
    op.add_column("vulnerabilities", sa.Column("section_id", sa.String, nullable=True))
    op.add_column("vulnerabilities", sa.Column("worker_type", sa.String, nullable=True))
    op.add_column("vulnerabilities", sa.Column("stage_name", sa.String, nullable=True))
    op.add_column("vulnerabilities", sa.Column("source_tool", sa.String, nullable=True))
    op.add_column("vulnerabilities", sa.Column("title", sa.String, nullable=True))
    op.add_column("vulnerabilities", sa.Column("evidence", sa.JSON, nullable=True))
    op.add_column("vulnerabilities", sa.Column("remediation", sa.Text, nullable=True))
    op.add_column("vulnerabilities", sa.Column("false_positive", sa.Boolean, server_default="false"))

    # 3. Add new columns to job_state
    op.add_column("job_state", sa.Column("current_section_id", sa.String, nullable=True))
    op.add_column("job_state", sa.Column("skipped", sa.Boolean, server_default="false"))
    op.add_column("job_state", sa.Column("skip_reason", sa.String, nullable=True))
    op.add_column("job_state", sa.Column("queued_at", sa.DateTime, nullable=True))
    op.add_column("job_state", sa.Column("started_at", sa.DateTime, nullable=True))
    op.add_column("job_state", sa.Column("completed_at", sa.DateTime, nullable=True))
    op.add_column("job_state", sa.Column("retry_count", sa.Integer, server_default="0"))

    # 4. Create new tables
    op.create_table("campaigns",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String, server_default="pending"),
        sa.Column("scope_config", sa.JSON, nullable=True),
        sa.Column("rate_limit", sa.Integer, server_default="50"),
        sa.Column("has_credentials", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime, server_default=func.now()),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )

    op.create_table("escalation_contexts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("vulnerability_id", sa.Integer, sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("access_type", sa.String, nullable=False),
        sa.Column("access_method", sa.Text, nullable=False),
        sa.Column("session_data", sa.Text, nullable=True),
        sa.Column("data_exposed", sa.Text, nullable=True),
        sa.Column("severity", sa.String, nullable=False),
        sa.Column("section_id", sa.String, nullable=True),
        sa.Column("consumed_by_chain", sa.Boolean, server_default="false"),
        sa.Column("chain_findings", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=func.now()),
    )

    op.create_table("chain_findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("escalation_context_id", sa.Integer, sa.ForeignKey("escalation_contexts.id"), nullable=False),
        sa.Column("chain_description", sa.Text, nullable=False),
        sa.Column("entry_vulnerability_id", sa.Integer, sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("linked_vulnerability_ids", sa.JSON, nullable=True),
        sa.Column("total_impact", sa.Text, nullable=True),
        sa.Column("severity", sa.String, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=func.now()),
    )

    # 5. Create indexes
    op.create_index("ix_targets_parent", "targets", ["parent_target_id"])
    op.create_index("ix_targets_campaign", "targets", ["campaign_id"])
    op.create_index("ix_targets_priority", "targets", ["priority"])
    op.create_index("ix_vulnerabilities_section", "vulnerabilities", ["section_id"])
    op.create_index("ix_vulnerabilities_worker", "vulnerabilities", ["worker_type"])
    op.create_index("ix_vulnerabilities_confirmed", "vulnerabilities", ["confirmed"])
    op.create_index("ix_job_state_target_worker", "job_state", ["target_id", "worker_type"])
    op.create_index("ix_escalation_target", "escalation_contexts", ["target_id"])
    op.create_index("ix_escalation_consumed", "escalation_contexts", ["consumed_by_chain"])


def downgrade():
    # Drop new tables
    op.drop_table("chain_findings")
    op.drop_table("escalation_contexts")
    op.drop_table("campaigns")

    # Drop new indexes
    op.drop_index("ix_escalation_consumed")
    op.drop_index("ix_escalation_target")
    op.drop_index("ix_job_state_target_worker")
    op.drop_index("ix_vulnerabilities_confirmed")
    op.drop_index("ix_vulnerabilities_worker")
    op.drop_index("ix_vulnerabilities_section")
    op.drop_index("ix_targets_priority")
    op.drop_index("ix_targets_campaign")
    op.drop_index("ix_targets_parent")

    # Drop new columns from existing tables
    op.drop_column("job_state", "retry_count")
    op.drop_column("job_state", "completed_at")
    op.drop_column("job_state", "started_at")
    op.drop_column("job_state", "queued_at")
    op.drop_column("job_state", "skip_reason")
    op.drop_column("job_state", "skipped")
    op.drop_column("job_state", "current_section_id")

    op.drop_column("vulnerabilities", "false_positive")
    op.drop_column("vulnerabilities", "remediation")
    op.drop_column("vulnerabilities", "evidence")
    op.drop_column("vulnerabilities", "title")
    op.drop_column("vulnerabilities", "source_tool")
    op.drop_column("vulnerabilities", "stage_name")
    op.drop_column("vulnerabilities", "worker_type")
    op.drop_column("vulnerabilities", "section_id")

    op.drop_column("targets", "campaign_id")
    op.drop_column("targets", "wildcard_count")
    op.drop_column("targets", "wildcard")
    op.drop_column("targets", "priority")
    op.drop_column("targets", "target_type")
    op.drop_column("targets", "parent_target_id")
```

### Data Migration

For existing data (if any targets/vulnerabilities exist from the current system):

```python
# alembic/versions/xxxx_migrate_existing_data.py

def upgrade():
    """Migrate existing data to new schema."""

    # 1. Create a default campaign for existing targets
    op.execute("""
        INSERT INTO campaigns (name, status, created_at)
        SELECT 'Legacy Campaign', 'complete', MIN(created_at)
        FROM targets
        HAVING COUNT(*) > 0
    """)

    # 2. Link existing targets to the default campaign
    op.execute("""
        UPDATE targets
        SET campaign_id = (SELECT id FROM campaigns WHERE name = 'Legacy Campaign'),
            target_type = 'seed'
        WHERE campaign_id IS NULL
    """)

    # 3. Map existing worker types to new worker types in job_state
    WORKER_MAPPING = {
        "recon_core": "info_gathering",
        "network_worker": "config_mgmt",
        "fuzzing_worker": "config_mgmt",
        "cloud_worker": "config_mgmt",
        "webapp_worker": "input_validation",
        "api_worker": "input_validation",
        "vuln_scanner": "input_validation",
    }

    for old_name, new_name in WORKER_MAPPING.items():
        op.execute(f"""
            UPDATE job_state
            SET worker_type = '{new_name}'
            WHERE worker_type = '{old_name}'
        """)
```

---

## Redis Stream Cleanup

The migration creates new streams and retires old ones:

```python
# orchestrator/migrate_redis.py

async def migrate_redis_streams():
    """Create new priority streams and retire old ones."""

    # Old streams to retire (drain first, then delete)
    OLD_STREAMS = ["recon_queue", "fuzzing_queue", "cloud_queue", "api_queue"]

    # New streams to create
    for worker_name in WORKER_QUEUES:
        queue_prefix = WORKER_QUEUES[worker_name]
        for tier in PRIORITY_TIERS:
            stream_name = f"{queue_prefix}:{tier}"
            group_name = f"{worker_name}_group"

            # Create consumer group (creates stream implicitly if MKSTREAM)
            try:
                await redis.xgroup_create(
                    stream_name, group_name, id="0", mkstream=True
                )
            except Exception:
                pass  # Group already exists

    # Drain and delete old streams
    for stream in OLD_STREAMS:
        pending = await redis.xlen(stream)
        if pending > 0:
            logger.warning(
                f"Old stream {stream} has {pending} pending messages. "
                "These will be lost. Ensure no active campaigns before migrating."
            )
        await redis.delete(stream)
```
