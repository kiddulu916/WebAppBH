# Dashboard UI/UX Overhaul — Design Document

**Date:** 2026-05-03
**Goal:** Remove legacy pipeline UI, build accurate 18-worker pipeline with infrastructure shelf, restyle all components to NEONHIVE tokens, simplify the C2 page, and fix campaign detail pages.

---

## 1. Dead Code Purge

Delete these files:
- `dashboard/src/components/c2/PhasePipeline.tsx`
- `dashboard/src/components/c2/WorkerGrid.tsx`
- `dashboard/src/components/c2/WorkerCard.tsx`
- `dashboard/src/components/c2/StatusBoard.tsx`
- `dashboard/src/components/c2/WorkerFeed.tsx`
- `dashboard/src/components/c2/WorkerConsole.tsx`

Remove all references to deleted legacy workers from types and constants:
- Remove `recon_core`, `network_worker`, `fuzzing_worker`, `cloud_worker`, `webapp_worker`, `api_worker`, `vuln_scanner` from any dashboard-side worker name lists, stage counts, or dependency maps.

Keep: `pipeline/WorkerCard.tsx`, `pipeline/PipelineGrid.tsx`, `pipeline/WorkerDetailDrawer.tsx` — these are the correct components to update.

---

## 2. Pipeline Overhaul — 18-Worker Layout

### Canonical worker list (18 total)

**Infrastructure (always-on, no dependencies):**
- proxy
- callback
- sandbox_worker

**Pipeline (sequential/parallel dependency graph):**
- info_gathering
- config_mgmt
- identity_mgmt
- authentication
- authorization
- session_mgmt
- input_validation
- error_handling
- cryptography
- business_logic
- client_side
- mobile_worker
- reasoning_worker
- chain_worker
- reporting

### Dependency graph

```
proxy: []
callback: []
sandbox_worker: []
info_gathering: []
config_mgmt: [info_gathering]
identity_mgmt: [config_mgmt]
authentication: [identity_mgmt]
authorization: [authentication]
session_mgmt: [authentication]
input_validation: [authentication]
error_handling: [authorization, session_mgmt, input_validation]
cryptography: [authorization, session_mgmt, input_validation]
business_logic: [authorization, session_mgmt, input_validation]
client_side: [authorization, session_mgmt, input_validation]
mobile_worker: [authorization, session_mgmt, input_validation]
reasoning_worker: [error_handling, cryptography, business_logic, client_side, mobile_worker]
chain_worker: [reasoning_worker]
reporting: [chain_worker]
```

### Visual layout

```
┌─ INFRASTRUCTURE ──────────────────────────────────────────┐
│  proxy              callback            sandbox_worker     │
└────────────────────────────────────────────────────────────┘

Row 1: info_gathering → config_mgmt → identity_mgmt → authentication
Row 2: authorization, session_mgmt, input_validation
Row 3: error_handling, cryptography, business_logic, client_side, mobile_worker
Row 4: reasoning_worker → chain_worker
Row 5: reporting
```

### Infrastructure shelf behavior

- Visually distinct: dashed border or subtle background difference, "INFRASTRUCTURE" section label.
- Smaller/compact cards: no progress bar, no stage count — just name + status dot.
- Running state uses `animate-pulse-green` (always-on services glow green, not orange).
- WorkerCard gets an `isInfra` variant prop to control this.

### Files to update

- `types/schema.ts` — update `WSTG_WORKER_NAMES` (rename to `WORKER_NAMES`), `WORKER_STAGE_COUNTS`, `WORKER_DEPENDENCIES`
- `pipeline/PipelineGrid.tsx` — new row layout with infrastructure shelf
- `pipeline/WorkerCard.tsx` — add `isInfra` variant
- `lib/wstg-stages.ts` — rename file to `worker-stages.ts`, add stage definitions for 5 new workers, remove "WSTG" from all exports
- `c2/page.tsx` — remove imports of deleted components, keep `jobsToWorkerStates()` as-is

### Global: Remove "WSTG" string

Remove the string "WSTG" from all dashboard files — component labels, section headers, variable names, type names, file names. Replace with plain "Pipeline" or "Worker" naming.

---

## 3. NEONHIVE Restyle Audit

Sweep every component for raw Tailwind color classes. Replace with NEONHIVE CSS variable tokens.

### Color mapping rules

| Raw Tailwind | NEONHIVE token |
|---|---|
| `text-gray-400/500` | `text-text-muted` |
| `text-amber-400` | `text-neon-orange` |
| `text-green-400` | `text-neon-green` |
| `text-blue-400` | `text-neon-blue` |
| `text-red-400` | `text-danger` |
| `text-yellow-400` | `text-warning` |
| `bg-gray-500/20` | `bg-bg-surface` |
| `bg-amber-500/20` | `bg-neon-orange-glow` |
| `bg-green-500/20` | `bg-neon-green-glow` |
| `bg-blue-500/20` | `bg-neon-blue-glow` |
| `bg-red-500/20` | `bg-danger/10` |
| `border-gray-600` | `border-border` |

### Severity badges

Use `--sev-critical`, `--sev-high`, `--sev-medium`, `--sev-low`, `--sev-info` tokens.

### Focus rings and buttons

- Form inputs use `input-focus` class
- Primary action buttons use `btn-launch` class

### Files to audit

- `campaign/[id]/layout.tsx`
- `campaign/[id]/overview/page.tsx`
- `campaign/[id]/targets/page.tsx`, `[targetId]/page.tsx`
- `campaign/[id]/findings/page.tsx`, `[vulnId]/page.tsx`
- `campaign/[id]/chains/page.tsx`, `[chainId]/page.tsx`
- `campaign/new/page.tsx`
- `components/findings/FindingsTable.tsx`, `FindingDetail.tsx`
- `components/targets/TargetRow.tsx`, `TargetTree.tsx`
- `components/chains/ChainList.tsx`, `ChainDetail.tsx`
- `components/resource/ResourceIndicator.tsx`, `ResourcePanel.tsx`
- `components/terminal/LiveTerminal.tsx`

---

## 4. C2 Page Simplification

### Remove from C2 page

- `WorkerHealthPanel` — redundant with new pipeline grid
- `WorkerGrid` / `SplitConsole` — replaced by pipeline grid + worker detail drawer
- `CampaignTimeline` — move into Worker Detail Drawer as collapsible section

### Reorganize remaining widgets

```
1. Page header (domain badge, rerun, settings)
2. Infrastructure shelf + Pipeline grid
3. Asset Tree (1/3) + Live terminal or event feed (2/3)
4. System Pulse (1/2) + Queue Health (1/2)
5. Diff Timeline (1/2) + Scope Drift Alerts (1/2)
```

Reduces from 9 stacked widgets to 5 clear sections.

---

## 5. Campaign Detail Pages

All pages fetch from `lib/api.ts` → orchestrator `/api/v1/` endpoints. No mock data.

### Overview

- Embed new PipelineGrid with infrastructure shelf
- Stats cards from real worker states
- No "WSTG" labels

### Targets

- List targets via `api.getTargets()`
- `TargetRow`: domain, status, asset count
- `TargetTree`: reuse `AssetTree` component from C2
- Detail page: full asset breakdown + link to C2

### Findings

- `FindingsTable`: TanStack Table, sortable/filterable
- Severity badges use `--sev-*` tokens
- `FindingDetail`: full vuln info, affected asset, evidence, chain membership

### Chains

- `ChainList`: attack chains from chain_worker
- `ChainDetail`: linked vulnerability sequence with visual flow

### Reports

- Wire `ReportList` and `ReportViewer` to API

### Missing orchestrator endpoints

If any endpoint needed by the dashboard doesn't exist, add it to `orchestrator/main.py`.
