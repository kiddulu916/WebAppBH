# WSTG-Aligned Restructure — 11 Dashboard & Reporting

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview, restructure-09-orchestrator, restructure-10-database-messaging
**Scope:** Campaign creator UI, pipeline progress grid, target hierarchy, reporting worker

---

## Overview

The dashboard is the operator's window into the framework. The restructured dashboard reflects the new worker architecture: WSTG-aligned worker progress, target hierarchy (seed → child), resource guard status, and vulnerability findings. The reporting worker produces bug submission reports only — progress tracking is a dashboard responsibility.

---

# Part A: Dashboard Changes

## Campaign Creator

The campaign creator is the entry point. It collects everything the orchestrator needs to start a campaign.

### Form Layout

```
┌─────────────────────────────────────────────────────┐
│ NEW CAMPAIGN                                         │
├─────────────────────────────────────────────────────┤
│                                                      │
│ Campaign Name: [________________________]            │
│ Description:   [________________________]            │
│                                                      │
│ ── SEED TARGETS ──                                   │
│ [target.com              ] [+ Add]                   │
│ [api.target.com          ] [x]                       │
│                                                      │
│ ── SCOPE CONFIGURATION ──                            │
│ In-scope patterns:                                   │
│ [*.target.com            ] [+ Add]                   │
│ [10.0.0.0/24             ] [+ Add]                   │
│                                                      │
│ Out-of-scope patterns:                               │
│ [blog.target.com         ] [+ Add]                   │
│ [*.cdn.target.com        ] [+ Add]                   │
│                                                      │
│ ── CREDENTIALS (Optional) ──                         │
│ ┌─ Tester Credentials ─────────────────────┐         │
│ │ Username: [______________]                │         │
│ │ Password: [______________]                │         │
│ │ Auth Type: [Form ▼]                       │         │
│ │   Form | Basic | Bearer | OAuth           │         │
│ │ Login URL: [______________] (for Form)    │         │
│ └───────────────────────────────────────────┘         │
│                                                      │
│ ┌─ Testing User ────────────────────────────┐        │
│ │ Username: [______________]                │         │
│ │ Email:    [______________] (fallback ID)  │         │
│ │ Profile URL: [______________] (optional)  │         │
│ │                                           │         │
│ │ ⚠ No password — this user is the          │         │
│ │   permitted victim for exploit             │         │
│ │   confirmation only.                       │         │
│ └───────────────────────────────────────────┘         │
│                                                      │
│ ── RATE LIMITING ──                                  │
│ Max requests/sec: [50___]                            │
│                                                      │
│ [Cancel]                          [Start Campaign]   │
└─────────────────────────────────────────────────────┘
```

### Validation Rules

- At least one seed target required
- At least one in-scope pattern required
- If Tester Credentials provided, Testing User must also be provided
- Testing User must not have a password field (safety enforcement)
- Auth Type determines which login fields are shown (Form shows login URL, Bearer shows token field, OAuth shows token endpoint)
- Rate limit minimum: 1, maximum: 200, default: 50

---

## Pipeline Progress Grid

The main campaign view shows all workers for a target in a dependency-aware grid layout.

### Grid Layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ CAMPAIGN: target.com                                    [Resource: 🟢]  │
│ Seed Target: target.com                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐                                                        │
│  │info_gathering │ ████████████ 100%                                     │
│  │  10/10 stages │                                                       │
│  └──────┬───────┘                                                        │
│         │                                                                │
│  ┌──────┴───────┐                                                        │
│  │ config_mgmt  │ ████████░░░░  67%                                      │
│  │  7/11 stages │                                                        │
│  └──────┬───────┘                                                        │
│         │                                                                │
│  ┌──────┴───────┐                                                        │
│  │identity_mgmt │ ░░░░░░░░░░░░ queued                                   │
│  │  0/5 stages  │                                                        │
│  └──────┬───────┘                                                        │
│         │                                                                │
│  ┌──────┴──────┐                                                         │
│  │authentication│ ░░░░░░░░░░░░ pending                                  │
│  │  0/10 stages │                                                        │
│  └──┬───────┬──┘                                                         │
│     │       │                                                            │
│  ┌──┴─────┐ ┌┴──────────┐                                               │
│  │ authz  │ │session_mgmt│  ← parallel                                  │
│  │ 0/4    │ │ 0/9        │                                               │
│  └──┬─────┘ └┬───────────┘                                               │
│     │        │                                                           │
│  ┌──┴────────┴──┐                                                        │
│  │input_validatn│ ░░░░░░░░░░░░ pending                                  │
│  │  0/15 stages │                                                        │
│  └──────┬───────┘                                                        │
│         │                                                                │
│  ┌──────┴──────┬────────────┬──────────────┬────────────┐                │
│  │error_handlng│cryptography│business_logic│ client_side│  ← parallel   │
│  │  0/2        │  0/4       │  0/9         │  0/13      │                │
│  └──────┬──────┴─────┬──────┴──────┬───────┴─────┬──────┘                │
│         │            │             │             │                        │
│  ┌──────┴────────────┴─────────────┴─────────────┴──┐                    │
│  │              chain_worker                         │ pending            │
│  └──────────────────────┬────────────────────────────┘                    │
│                         │                                                │
│  ┌──────────────────────┴────────────────────────────┐                    │
│  │              reporting                            │ pending            │
│  └───────────────────────────────────────────────────┘                    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Worker Status Colors

| Status | Color | Description |
|--------|-------|-------------|
| pending | Gray | Dependencies not yet met |
| queued | Blue | Enqueued, waiting for worker container |
| running | Amber (animated pulse) | Actively processing stages |
| complete | Green | All stages finished |
| failed | Red | Error encountered |
| skipped | Dim gray, dashed border | Skipped (no credentials, etc.) |

### Worker Detail Drawer

Clicking a worker card opens a side drawer showing:

```
┌─────────────────────────────────────────┐
│ config_mgmt — target.com               │
│ Status: running (stage 7/11)            │
│ Started: 2026-03-29 14:23:07            │
│ Duration: 12m 34s                       │
├─────────────────────────────────────────┤
│ Stages:                                 │
│ ✅ 4.2.1  network_config       1m 12s  │
│ ✅ 4.2.2  platform_config      0m 45s  │
│ ✅ 4.2.3  file_extension_handling 2m 3s │
│ ✅ 4.2.4  backup_files          3m 21s  │
│ ✅ 4.2.5  api_discovery         1m 56s  │
│ ✅ 4.2.6  http_methods          0m 38s  │
│ 🔄 4.2.7  hsts_testing          ...     │
│ ⏳ 4.2.8  rpc_testing                   │
│ ⏳ 4.2.9  file_inclusion                │
│ ⏳ 4.2.10 subdomain_takeover            │
│ ⏳ 4.2.11 cloud_storage                 │
├─────────────────────────────────────────┤
│ Findings so far: 3 vulns (1H, 2M)      │
│ [View Findings]                         │
└─────────────────────────────────────────┘
```

---

## Target Hierarchy View

For campaigns with child targets, a hierarchy view shows the tree:

```
┌──────────────────────────────────────────────────────────┐
│ TARGET HIERARCHY — Campaign: target.com                   │
├──────────────────────────────────────────────────────────┤
│                                                           │
│ 📊 Summary: 42 children discovered, 28 complete,          │
│             8 running, 4 queued, 2 pending                │
│                                                           │
│ ▼ target.com (seed) ✅ complete — 12 vulns               │
│   ├── api.target.com (P:95) ✅ complete — 8 vulns        │
│   ├── admin.target.com (P:90) 🔄 running — 3 vulns      │
│   ├── portal.target.com (P:85) 🔄 running — 1 vuln      │
│   ├── staging.target.com (P:80) 🔄 running               │
│   ├── dev.target.com (P:75) 📋 queued                    │
│   ├── auth.target.com (P:75) 📋 queued                   │
│   ├── mail.target.com (P:60) ✅ complete — 2 vulns       │
│   ├── blog.target.com (P:55) ✅ complete — 0 vulns       │
│   ├── docs.target.com (P:50) ⏳ pending                  │
│   ├── cdn.target.com (P:25) ⏳ pending                   │
│   └── ... 32 more                                        │
│                                                           │
│ Filter: [All ▼] [Running ▼] Sort: [Priority ▼]          │
└──────────────────────────────────────────────────────────┘
```

Each child target row is clickable, expanding to show the same pipeline progress grid as the seed target.

---

## Resource Guard Dashboard

A persistent resource indicator in the top navigation bar shows current system health:

```
┌─ Resource Guard ─────────────────────────────────────────┐
│ Tier: 🟢 GREEN                                           │
│                                                           │
│ CPU:     ████████░░░░░░░░  45%   (threshold: 60%)       │
│ Memory:  ██████░░░░░░░░░░  38%   (threshold: 60%)       │
│ Workers: ███░░░░░░░░░░░░░  5/8   (threshold: 8)         │
│                                                           │
│ Active queues: critical (2), high (5), normal (12)       │
│ Processing rate: 3 targets/min                            │
│                                                           │
│ [Override Tier ▼]  [Adjust Thresholds]                   │
└──────────────────────────────────────────────────────────┘
```

The tier indicator in the top bar is a small colored dot:
- 🟢 Green — full speed
- 🟡 Yellow — reduced throughput
- 🔴 Red — throttled
- ⚫ Critical — paused

Clicking the dot expands the full resource panel.

---

## Findings View

The findings view aggregates all Vulnerability records across a campaign's targets.

### Table Columns

| Column | Description |
|--------|-------------|
| Severity | Critical / High / Medium / Low / Info with color-coded badge |
| Title | Vulnerability title |
| Target | Which target (seed or child) |
| Worker | Which worker found it (e.g., input_validation) |
| Stage | Which stage (e.g., sql_injection) |
| Section | WSTG section reference (e.g., 4.7.5) |
| Tool | Which tool found it (e.g., SqlmapTool) |
| Confirmed | Boolean — whether the exploit was verified |
| Actions | View details, mark as false positive, export |

### Filters

- Severity filter (multi-select)
- Worker filter (multi-select)
- Target filter (seed/child selector)
- Confirmed/unconfirmed toggle
- False positive visibility toggle
- Section range filter (e.g., "4.7.*" for all input_validation findings)

### Finding Detail View

Clicking a finding opens a detail panel:

```
┌─────────────────────────────────────────────────────────┐
│ SQL Injection — login endpoint                           │
│ Section: 4.7.5 | Severity: CRITICAL | Confirmed: ✅     │
├─────────────────────────────────────────────────────────┤
│ Target: api.target.com                                   │
│ Worker: input_validation | Stage: sql_injection          │
│ Tool: SqlmapTool                                         │
│ Found: 2026-03-29 15:42:18                               │
├─────────────────────────────────────────────────────────┤
│ Description:                                             │
│ Time-based blind SQL injection in the `username`         │
│ parameter of POST /api/v1/auth/login. The application    │
│ uses MySQL 8.0 with no parameterized queries on the      │
│ login endpoint.                                          │
├─────────────────────────────────────────────────────────┤
│ Evidence:                                                │
│ ┌─ Request ──────────────────────────────────┐           │
│ │ POST /api/v1/auth/login HTTP/1.1           │           │
│ │ Content-Type: application/json             │           │
│ │                                            │           │
│ │ {"username":"admin' AND SLEEP(5)-- -",     │           │
│ │  "password":"test"}                        │           │
│ └────────────────────────────────────────────┘           │
│ ┌─ Response (5.12s) ─────────────────────────┐           │
│ │ HTTP/1.1 401 Unauthorized                  │           │
│ │ X-Response-Time: 5124ms                    │           │
│ └────────────────────────────────────────────┘           │
├─────────────────────────────────────────────────────────┤
│ Remediation:                                             │
│ Use parameterized queries or an ORM for all database     │
│ operations. Never concatenate user input into SQL.       │
├─────────────────────────────────────────────────────────┤
│ Chain Context:                                           │
│ This vulnerability was consumed by chain_worker.         │
│ Chain finding: SQLi -> data exfil -> admin access        │
│ [View Chain Finding #12]                                 │
├─────────────────────────────────────────────────────────┤
│ [Mark False Positive]  [Export to Report]  [Close]       │
└─────────────────────────────────────────────────────────┘
```

---

## Live Terminal

The live terminal replaces toast notifications. It's a collapsible panel at the bottom of the dashboard that streams real-time events via SSE.

```
┌─ Live Terminal ────────────────────────────────────────┐
│ [14:23:07] config_mgmt started for target.com          │
│ [14:23:08] Stage 4.2.1 network_config started          │
│ [14:23:19] NetworkConfigTester complete (3 findings)   │
│ [14:24:15] Stage 4.2.2 platform_config started         │
│ [14:24:52] PlatformFingerprinter complete (1 finding)  │
│ [14:25:01] ⚠ VULN [HIGH] Exposed admin panel at       │
│            admin.target.com/.well-known/admin           │
│ [14:25:03] Stage 4.2.3 file_extension_handling started │
│ [14:27:06] 🎯 TARGET EXPANSION: 42 children created   │
│            for target.com (28 unique hosts)             │
│ [14:27:07] Resource guard: GREEN (CPU 45%, Mem 38%)    │
│ [14:28:12] ⚠ VULN [CRITICAL] SQL injection in         │
│            POST /api/v1/auth/login (api.target.com)    │
│ ___________________________________________________    │
│ Filter: [All Events ▼]  [Clear]  [Auto-scroll: ON]    │
└────────────────────────────────────────────────────────┘
```

### Event Types

| Event | Display |
|-------|---------|
| worker_queued | `{worker} queued for {target}` |
| worker_started | `{worker} started for {target}` |
| worker_complete | `{worker} complete for {target}` (green) |
| worker_failed | `{worker} FAILED for {target}: {error}` (red) |
| worker_skipped | `{worker} skipped for {target}: {reason}` (dim) |
| stage_started | `Stage {section_id} {stage_name} started` |
| stage_complete | `Stage {section_id} {stage_name} complete ({findings} findings)` |
| finding | `VULN [{severity}] {title} ({target})` (yellow/red) |
| escalated_access | `ESCALATED ACCESS: {access_type} via {method}` (red, bold) |
| target_expanded | `TARGET EXPANSION: {count} children created` (blue) |
| resource_tier_change | `Resource guard: {tier} (CPU {cpu}%, Mem {mem}%)` |

### Filter Options

- All Events
- Findings Only
- Worker Lifecycle Only
- Errors Only
- Specific Target

---

# Part B: Reporting Worker

**Worker Directory:** `workers/reporting/`
**Queue:** `reporting_queue`
**Trigger:** chain_worker complete

---

## Overview

The reporting worker produces bug submission reports. These are formatted for direct submission to bug bounty platforms — not progress reports. Progress tracking lives in the dashboard (pipeline grid, live terminal, findings table).

---

## Report Types

### 1. Individual Bug Report

One report per confirmed vulnerability. Formatted for HackerOne/Bugcrowd/Intigriti submission.

```markdown
## Title
SQL Injection in login endpoint — api.target.com

## Severity
Critical (CVSS 9.8)

## Summary
A time-based blind SQL injection vulnerability exists in the `username`
parameter of the POST /api/v1/auth/login endpoint on api.target.com.
An unauthenticated attacker can extract arbitrary data from the MySQL
database, including user credentials and session tokens.

## Steps to Reproduce
1. Navigate to https://api.target.com/api/v1/auth/login
2. Intercept the login request with a proxy
3. Modify the `username` parameter:
   ```
   admin' AND SLEEP(5)-- -
   ```
4. Observe a 5-second delay in the server response, confirming
   time-based blind SQL injection

## Proof of Concept
### Request
```http
POST /api/v1/auth/login HTTP/1.1
Host: api.target.com
Content-Type: application/json

{"username":"admin' AND SLEEP(5)-- -","password":"test"}
```

### Response
```http
HTTP/1.1 401 Unauthorized
X-Response-Time: 5124ms
```

### Comparison (normal request)
```http
POST /api/v1/auth/login HTTP/1.1
Host: api.target.com
Content-Type: application/json

{"username":"admin","password":"test"}
```

Response time: 42ms (vs 5124ms with injection payload)

## Impact
An attacker can:
- Extract all user credentials from the database
- Bypass authentication entirely
- Access administrative functionality
- Potentially achieve remote code execution via MySQL
  `INTO OUTFILE` or UDF

## Affected Endpoint
- URL: https://api.target.com/api/v1/auth/login
- Method: POST
- Parameter: `username` (body, JSON)
- Backend: MySQL 8.0

## Remediation
Use parameterized queries or an ORM for all database operations.
Never concatenate user input into SQL statements.

## References
- OWASP Testing Guide Section 4.7.5
- CWE-89: SQL Injection
```

### 2. Vulnerability Chain Report

One report per chain finding. Documents the full attack chain with individual steps.

```markdown
## Title
Authentication Bypass to Admin Panel via SQL Injection + IDOR Chain

## Severity
Critical

## Summary
A chain of three vulnerabilities allows an unauthenticated attacker to
gain full administrative access to the application:
1. SQL Injection in login endpoint extracts admin session token
2. Session fixation allows reuse of extracted token
3. IDOR in admin API exposes all user data

## Attack Chain
### Step 1: SQL Injection (Section 4.7.5)
[Full PoC from individual finding #42]

### Step 2: Session Token Reuse (Section 4.6.3)
[Full PoC from individual finding #67]

### Step 3: IDOR in Admin API (Section 4.5.4)
[Full PoC from individual finding #83]

## Combined Impact
An unauthenticated attacker can access all user PII, modify any account,
and perform administrative actions including user deletion and
configuration changes.

## Affected Components
- /api/v1/auth/login (SQLi entry point)
- Session management (no token rotation)
- /api/v1/admin/users/{id} (IDOR)
```

---

## Report Generation Pipeline

```python
# workers/reporting/pipeline.py

STAGES = [
    Stage(
        name="generate_reports",
        section_id="report",
        tools=[ReportGenerator],
    ),
]
```

### ReportGenerator Tool

```python
# workers/reporting/tools/report_generator.py

class ReportGenerator:
    """Generates bug submission reports from vulnerability data.

    Produces:
    1. Individual bug reports for each confirmed vulnerability
    2. Chain reports for each chain_finding record
    """

    async def execute(self, target_id):
        async with get_session() as session:
            # Get all confirmed, non-false-positive vulnerabilities
            vulns = await session.execute(
                select(Vulnerability)
                .where(Vulnerability.target_id == target_id)
                .where(Vulnerability.confirmed == True)
                .where(Vulnerability.false_positive == False)
                .order_by(Vulnerability.severity.desc())
            )

            for vuln in vulns.scalars().all():
                report = self._generate_individual_report(vuln)
                await self._save_report(target_id, vuln.id, report)

            # Get chain findings
            chains = await session.execute(
                select(ChainFinding)
                .where(ChainFinding.target_id == target_id)
            )

            for chain in chains.scalars().all():
                report = self._generate_chain_report(chain)
                await self._save_report(
                    target_id, chain.entry_vulnerability_id, report,
                    report_type="chain"
                )
```

### Report Storage

Reports are saved as Markdown files in `shared/reports/{campaign_id}/{target_domain}/`:

```
shared/reports/
└── 1/                          # campaign_id
    └── target.com/             # seed target
        ├── individual/
        │   ├── vuln-042-sqli-login.md
        │   ├── vuln-067-session-fixation.md
        │   └── vuln-083-idor-admin.md
        └── chains/
            └── chain-001-sqli-to-admin.md
```

### Report Export

The dashboard provides export options:
- **Download individual** — single report as Markdown or PDF
- **Download all** — ZIP archive of all reports for a campaign
- **Copy to clipboard** — for direct paste into bug bounty platform submission forms

---

## Dashboard API Endpoints for Reporting

```
GET  /api/v1/campaigns/{id}/reports           — List all reports
GET  /api/v1/campaigns/{id}/reports/{vuln_id} — Get individual report
GET  /api/v1/campaigns/{id}/reports/chains     — List chain reports
GET  /api/v1/campaigns/{id}/reports/export     — Download ZIP of all reports
GET  /api/v1/campaigns/{id}/reports/stats      — Report statistics (counts by severity)
```

---

# Part C: Dashboard Page Structure

```
/campaign/
├── new                          — Campaign creator form
├── [id]/
│   ├── overview                 — Pipeline progress grid (seed target)
│   ├── targets                  — Target hierarchy view
│   ├── targets/[targetId]       — Pipeline progress for specific child
│   ├── findings                 — Aggregated vulnerability table
│   ├── findings/[vulnId]        — Finding detail view
│   ├── chains                   — Chain findings view
│   ├── chains/[chainId]         — Chain detail view
│   ├── reports                  — Generated reports list
│   ├── reports/[reportId]       — Individual report view
│   └── settings                 — Campaign settings, credential management
```

---

# Part D: SSE Integration

### Event Source Connection

```typescript
// src/hooks/useTargetEvents.ts

export function useTargetEvents(targetId: number) {
  const [events, setEvents] = useState<TargetEvent[]>([]);

  useEffect(() => {
    const source = new EventSource(`/api/sse/${targetId}`);

    source.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents((prev) => [...prev.slice(-500), data]); // Keep last 500 events
    };

    return () => source.close();
  }, [targetId]);

  return events;
}
```

### Event-Driven State Updates

The dashboard uses SSE events to update the pipeline grid in real-time without polling:

```typescript
// src/stores/pipelineStore.ts

interface PipelineState {
  workerStates: Record<string, WorkerState>;
  updateFromEvent: (event: TargetEvent) => void;
}

export const usePipelineStore = create<PipelineState>((set) => ({
  workerStates: {},

  updateFromEvent: (event) => {
    switch (event.event) {
      case "worker_started":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker]: { status: "running", startedAt: event.timestamp },
          },
        }));
        break;

      case "worker_complete":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker]: { status: "complete", completedAt: event.timestamp },
          },
        }));
        break;

      case "stage_complete":
        set((state) => {
          const worker = state.workerStates[event.worker] || {};
          return {
            workerStates: {
              ...state.workerStates,
              [event.worker]: {
                ...worker,
                currentStage: event.stage_index + 1,
                lastSectionId: event.section_id,
              },
            },
          };
        });
        break;

      // ... other event types
    }
  },
}));
```
