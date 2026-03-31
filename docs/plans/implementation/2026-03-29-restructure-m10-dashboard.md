# M10: Dashboard Updates Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Update the Next.js dashboard with campaign management, WSTG-aligned pipeline progress grid, target hierarchy view, resource guard indicator, findings table, chain findings, report management, and live terminal.

**Architecture:** Next.js 16 + React 19 + Zustand + TanStack Table + Tailwind v4. SSE-driven real-time updates. All data fetched from orchestrator API (`/api/v1/`).

**Tech Stack:** Next.js 16, React 19, TypeScript, Zustand, TanStack React Table, Tailwind CSS v4, Lucide icons, Sonner toasts

**Design doc:** `docs/plans/design/2026-03-29-restructure-11-dashboard-reporting.md`

---

## Task 1: Campaign API Types & Zustand Store

**Files:**
- Create: `dashboard/src/types/campaign.ts`
- Create: `dashboard/src/stores/campaignStore.ts`
- Modify: `dashboard/src/types/index.ts` (re-export)

**Step 1: Create campaign types**

```typescript
// dashboard/src/types/campaign.ts

export interface Campaign {
  id: number;
  name: string;
  description: string | null;
  status: "pending" | "running" | "paused" | "complete" | "cancelled";
  scope_config: ScopeConfig | null;
  rate_limit: number;
  has_credentials: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScopeConfig {
  in_scope: string[];
  out_of_scope: string[];
}

export interface CredentialConfig {
  tester: {
    username: string;
    password: string;
    auth_type: "form" | "basic" | "bearer" | "oauth";
    login_url?: string;
  } | null;
  testing_user: {
    username: string;
    email: string;
    profile_url?: string;
  } | null;
}

export interface WorkerState {
  status: "pending" | "queued" | "running" | "complete" | "failed" | "skipped";
  current_stage_index?: number;
  total_stages?: number;
  current_section_id?: string;
  last_tool_executed?: string;
  started_at?: string;
  completed_at?: string;
  skipped?: boolean;
  skip_reason?: string;
  error?: string;
}

export interface TargetNode {
  id: number;
  domain: string;
  target_type: "seed" | "child";
  priority: number;
  status: string;
  wildcard: boolean;
  wildcard_count: number | null;
  parent_target_id: number | null;
  worker_states: Record<string, WorkerState>;
  vulnerability_count: number;
  children?: TargetNode[];
}

export interface ResourceStatus {
  tier: "green" | "yellow" | "red" | "critical";
  cpu_percent: number;
  memory_percent: number;
  active_workers: number;
  thresholds: {
    green: { cpu: number; memory: number; workers: number };
    yellow: { cpu: number; memory: number; workers: number };
    red: { cpu: number; memory: number; workers: number };
  };
}

export interface TargetEvent {
  event: string;
  worker?: string;
  target_id: number;
  timestamp: string;
  data?: Record<string, unknown>;
  stage_index?: number;
  section_id?: string;
  stage_name?: string;
  severity?: string;
  title?: string;
  error?: string;
  count?: number;
}

export interface Finding {
  id: number;
  target_id: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  vuln_type: string;
  section_id: string | null;
  worker_type: string | null;
  stage_name: string | null;
  source_tool: string | null;
  confirmed: boolean;
  false_positive: boolean;
  description: string | null;
  evidence: Record<string, unknown> | null;
  remediation: string | null;
  created_at: string;
  target_domain?: string;
}

export interface ChainFindingView {
  id: number;
  target_id: number;
  chain_description: string;
  severity: string;
  total_impact: string | null;
  linked_vulnerability_ids: number[] | null;
  created_at: string;
}
```

**Step 2: Create campaign store**

```typescript
// dashboard/src/stores/campaignStore.ts
import { create } from "zustand";
import type { Campaign } from "@/types/campaign";

interface CampaignState {
  campaigns: Campaign[];
  activeCampaign: Campaign | null;
  loading: boolean;
  setCampaigns: (campaigns: Campaign[]) => void;
  setActiveCampaign: (campaign: Campaign | null) => void;
  setLoading: (loading: boolean) => void;
}

export const useCampaignStore = create<CampaignState>((set) => ({
  campaigns: [],
  activeCampaign: null,
  loading: false,
  setCampaigns: (campaigns) => set({ campaigns }),
  setActiveCampaign: (campaign) => set({ activeCampaign: campaign }),
  setLoading: (loading) => set({ loading }),
}));
```

**Step 3: Commit**

```bash
git add dashboard/src/types/campaign.ts dashboard/src/stores/campaignStore.ts
git commit -m "feat(dashboard): add campaign types and Zustand store"
```

---

## Task 2: Pipeline Store (SSE-driven)

**Files:**
- Create: `dashboard/src/stores/pipelineStore.ts`
- Modify: `dashboard/src/hooks/useTargetEvents.ts`

**Step 1: Create pipeline store**

```typescript
// dashboard/src/stores/pipelineStore.ts
import { create } from "zustand";
import type { WorkerState, TargetEvent, ResourceStatus } from "@/types/campaign";

interface PipelineState {
  workerStates: Record<string, WorkerState>;
  resourceStatus: ResourceStatus | null;
  updateFromEvent: (event: TargetEvent) => void;
  setWorkerStates: (states: Record<string, WorkerState>) => void;
  setResourceStatus: (status: ResourceStatus) => void;
}

export const usePipelineStore = create<PipelineState>((set) => ({
  workerStates: {},
  resourceStatus: null,

  updateFromEvent: (event) => {
    switch (event.event) {
      case "worker_queued":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: { status: "queued" },
          },
        }));
        break;

      case "worker_started":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              status: "running",
              started_at: event.timestamp,
              current_stage_index: 0,
            },
          },
        }));
        break;

      case "worker_complete":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              ...state.workerStates[event.worker!],
              status: "complete",
              completed_at: event.timestamp,
            },
          },
        }));
        break;

      case "worker_failed":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              ...state.workerStates[event.worker!],
              status: "failed",
              error: event.error,
            },
          },
        }));
        break;

      case "worker_skipped":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              status: "skipped",
              skipped: true,
              skip_reason: event.data?.reason as string,
            },
          },
        }));
        break;

      case "stage_complete":
        set((state) => {
          const worker = state.workerStates[event.worker!] || {};
          return {
            workerStates: {
              ...state.workerStates,
              [event.worker!]: {
                ...worker,
                current_stage_index: (event.stage_index ?? 0) + 1,
                current_section_id: event.section_id,
              },
            },
          };
        });
        break;
    }
  },

  setWorkerStates: (states) => set({ workerStates: states }),
  setResourceStatus: (status) => set({ resourceStatus: status }),
}));
```

**Step 2: Update SSE hook**

```typescript
// dashboard/src/hooks/useTargetEvents.ts
import { useState, useEffect } from "react";
import type { TargetEvent } from "@/types/campaign";
import { usePipelineStore } from "@/stores/pipelineStore";

export function useTargetEvents(targetId: number) {
  const [events, setEvents] = useState<TargetEvent[]>([]);
  const updateFromEvent = usePipelineStore((s) => s.updateFromEvent);

  useEffect(() => {
    const source = new EventSource(`/api/sse/${targetId}`);

    source.onmessage = (event) => {
      const data: TargetEvent = JSON.parse(event.data);
      setEvents((prev) => [...prev.slice(-500), data]);
      updateFromEvent(data);
    };

    return () => source.close();
  }, [targetId, updateFromEvent]);

  return events;
}
```

**Step 3: Commit**

```bash
git add dashboard/src/stores/pipelineStore.ts dashboard/src/hooks/useTargetEvents.ts
git commit -m "feat(dashboard): add pipeline store with SSE-driven state updates"
```

---

## Task 3: Campaign Creator Page

**Files:**
- Create: `dashboard/src/app/campaign/new/page.tsx`

**Step 1: Implement campaign creator form**

The form collects: campaign name, description, seed targets (multi-input), scope config (in-scope/out-of-scope patterns), optional tester credentials, optional testing user, rate limit.

Validation:
- At least one seed target
- At least one in-scope pattern
- If tester credentials provided, testing user required
- Testing user must not have password field
- Rate limit 1-200, default 50

Submits POST to `/api/v1/campaigns`.

**Step 2: Commit**

```bash
git add dashboard/src/app/campaign/new/page.tsx
git commit -m "feat(dashboard): add campaign creator page with credential management"
```

---

## Task 4: Pipeline Progress Grid Component

**Files:**
- Create: `dashboard/src/components/pipeline/PipelineGrid.tsx`
- Create: `dashboard/src/components/pipeline/WorkerCard.tsx`
- Create: `dashboard/src/components/pipeline/WorkerDetailDrawer.tsx`

**Step 1: Implement PipelineGrid**

Renders the dependency-aware worker layout from the design doc. Each worker is a `WorkerCard` showing:
- Worker name
- Status color (pending=gray, queued=blue, running=amber-pulse, complete=green, failed=red, skipped=dim-dashed)
- Stage progress bar (e.g., "7/11 stages")
- Dependency lines connecting cards

Worker dependency layout (hardcoded, matching `orchestrator/dependency_map.py`):
```
info_gathering → config_mgmt → identity_mgmt → authentication
                                                → authorization + session_mgmt (parallel)
                                                → input_validation
                                                → error_handling + cryptography + business_logic + client_side (parallel)
                                                → chain_worker → reporting
```

**Step 2: Implement WorkerCard**

Displays a single worker's status. Color-coded border based on status. Shows stage count. Clickable — opens `WorkerDetailDrawer`.

**Step 3: Implement WorkerDetailDrawer**

Side drawer showing:
- Worker name, target, status
- Start time, duration
- Stage-by-stage progress list with WSTG section IDs
- Completed stages with checkmarks and durations
- Current stage with spinner
- Pending stages grayed out
- Finding count so far

**Step 4: Commit**

```bash
git add dashboard/src/components/pipeline/
git commit -m "feat(dashboard): add pipeline progress grid with worker cards and detail drawer"
```

---

## Task 5: Campaign Overview Page

**Files:**
- Create: `dashboard/src/app/campaign/[id]/overview/page.tsx`

**Step 1: Implement overview page**

Fetches campaign data from `GET /api/v1/campaigns/{id}` and target data from `GET /api/v1/targets/{id}/pipeline`. Renders:
- Campaign header (name, status, resource guard indicator)
- PipelineGrid for the seed target
- Summary stats (total children, vulns found, workers complete)
- Connects to SSE via `useTargetEvents` hook for real-time updates

**Step 2: Commit**

```bash
git add dashboard/src/app/campaign/[id]/overview/page.tsx
git commit -m "feat(dashboard): add campaign overview page with real-time pipeline grid"
```

---

## Task 6: Target Hierarchy View

**Files:**
- Create: `dashboard/src/app/campaign/[id]/targets/page.tsx`
- Create: `dashboard/src/components/targets/TargetTree.tsx`
- Create: `dashboard/src/components/targets/TargetRow.tsx`
- Create: `dashboard/src/app/campaign/[id]/targets/[targetId]/page.tsx`

**Step 1: Implement TargetTree**

Renders the seed → child hierarchy. Fetches from `GET /api/v1/targets/{id}/children`. Each row shows:
- Domain name
- Priority score (P:XX)
- Status icon (complete/running/queued/pending)
- Vulnerability count
- Expandable to show PipelineGrid for that child

**Step 2: Implement TargetRow**

Single row in the tree. Clickable — navigates to `/campaign/{id}/targets/{targetId}` which shows the full pipeline grid for that child target.

**Step 3: Implement child target page**

`/campaign/{id}/targets/{targetId}` — renders PipelineGrid for a specific child target. Same component as overview but for a different target ID.

**Step 4: Commit**

```bash
git add dashboard/src/app/campaign/[id]/targets/ dashboard/src/components/targets/
git commit -m "feat(dashboard): add target hierarchy view with child target drill-down"
```

---

## Task 7: Resource Guard Indicator

**Files:**
- Create: `dashboard/src/components/resource/ResourceIndicator.tsx`
- Create: `dashboard/src/components/resource/ResourcePanel.tsx`

**Step 1: Implement ResourceIndicator**

Small colored dot in the top navigation bar. Colors: green/yellow/red/black. Clickable — toggles `ResourcePanel`.

Polls `GET /api/v1/resources/status` every 10 seconds.

**Step 2: Implement ResourcePanel**

Expandable panel showing:
- Current tier with color
- CPU bar (current % vs threshold)
- Memory bar (current % vs threshold)
- Active workers count vs threshold
- Active queue breakdown
- Override tier dropdown (admin only)
- Adjust thresholds button

**Step 3: Commit**

```bash
git add dashboard/src/components/resource/
git commit -m "feat(dashboard): add resource guard indicator and management panel"
```

---

## Task 8: Findings Table Page

**Files:**
- Create: `dashboard/src/app/campaign/[id]/findings/page.tsx`
- Create: `dashboard/src/components/findings/FindingsTable.tsx`
- Create: `dashboard/src/components/findings/FindingDetail.tsx`
- Create: `dashboard/src/app/campaign/[id]/findings/[vulnId]/page.tsx`

**Step 1: Implement FindingsTable**

TanStack React Table with columns: Severity (badge), Title, Target, Worker, Stage, Section ID, Tool, Confirmed, Actions.

Filters: severity (multi-select), worker (multi-select), target, confirmed/unconfirmed toggle, false positive visibility, section range (e.g., "4.7.*").

Fetches from `GET /api/v1/targets/{id}/findings`.

**Step 2: Implement FindingDetail**

Full finding detail panel. Shows: title, severity badge, section ID, confirmed status, target, worker/stage/tool, description, evidence (request/response with code blocks), remediation, chain context (if consumed by chain_worker), mark-false-positive button, export button.

**Step 3: Implement finding detail page**

`/campaign/{id}/findings/{vulnId}` — renders FindingDetail as a full page.

**Step 4: Commit**

```bash
git add dashboard/src/app/campaign/[id]/findings/ dashboard/src/components/findings/
git commit -m "feat(dashboard): add findings table with filters and detail view"
```

---

## Task 9: Chain Findings View

**Files:**
- Create: `dashboard/src/app/campaign/[id]/chains/page.tsx`
- Create: `dashboard/src/components/chains/ChainList.tsx`
- Create: `dashboard/src/components/chains/ChainDetail.tsx`
- Create: `dashboard/src/app/campaign/[id]/chains/[chainId]/page.tsx`

**Step 1: Implement ChainList**

Lists all ChainFinding records. Shows: chain description summary, severity, linked vuln count, created date. Clickable rows.

**Step 2: Implement ChainDetail**

Full chain detail: step-by-step attack chain with linked individual vulnerabilities, total impact assessment, severity.

**Step 3: Commit**

```bash
git add dashboard/src/app/campaign/[id]/chains/ dashboard/src/components/chains/
git commit -m "feat(dashboard): add chain findings view with detail panel"
```

---

## Task 10: Reports Page

**Files:**
- Create: `dashboard/src/app/campaign/[id]/reports/page.tsx`
- Create: `dashboard/src/components/reports/ReportList.tsx`
- Create: `dashboard/src/components/reports/ReportViewer.tsx`
- Create: `dashboard/src/app/campaign/[id]/reports/[reportId]/page.tsx`

**Step 1: Implement ReportList**

Lists generated reports from `GET /api/v1/campaigns/{id}/reports`. Two tabs: Individual Reports, Chain Reports. Each row shows vuln title, severity, target domain. Action buttons: View, Download, Copy.

**Step 2: Implement ReportViewer**

Renders Markdown report content. Copy-to-clipboard button for direct paste into bug bounty forms. Download as .md button.

**Step 3: Add export all button**

Download all reports as ZIP via `GET /api/v1/campaigns/{id}/reports/export`.

**Step 4: Commit**

```bash
git add dashboard/src/app/campaign/[id]/reports/ dashboard/src/components/reports/
git commit -m "feat(dashboard): add reports page with viewer and export"
```

---

## Task 11: Live Terminal Component

**Files:**
- Create: `dashboard/src/components/terminal/LiveTerminal.tsx`

**Step 1: Implement LiveTerminal**

Collapsible panel at the bottom of the dashboard. Streams SSE events from `useTargetEvents`. Each event rendered as a timestamped log line with color coding:

- worker_started: white
- worker_complete: green
- worker_failed: red
- stage_started/complete: dim white
- finding: yellow (high/medium) or red (critical)
- escalated_access: red bold
- target_expanded: blue
- resource_tier_change: tier color

Features:
- Auto-scroll toggle
- Filter dropdown (All, Findings Only, Worker Lifecycle, Errors, Specific Target)
- Clear button
- Max 500 events (ring buffer)

**Step 2: Commit**

```bash
git add dashboard/src/components/terminal/LiveTerminal.tsx
git commit -m "feat(dashboard): add live terminal with SSE event streaming"
```

---

## Task 12: Campaign Layout & Navigation

**Files:**
- Create: `dashboard/src/app/campaign/[id]/layout.tsx`
- Modify: `dashboard/src/app/campaign/layout.tsx`

**Step 1: Implement campaign layout**

Wraps all `/campaign/[id]/*` pages with:
- Campaign header (name, status badge)
- Resource guard indicator
- Tab navigation: Overview | Targets | Findings | Chains | Reports | Settings
- Live terminal at the bottom (collapsed by default)

**Step 2: Commit**

```bash
git add dashboard/src/app/campaign/[id]/layout.tsx
git commit -m "feat(dashboard): add campaign layout with tab navigation and live terminal"
```

---

## Task 13: API Proxy Routes

**Files:**
- Create: `dashboard/src/app/api/campaigns/route.ts`
- Create: `dashboard/src/app/api/campaigns/[id]/route.ts`
- Create: `dashboard/src/app/api/campaigns/[id]/reports/route.ts`
- Create: `dashboard/src/app/api/resources/route.ts`

**Step 1: Implement API proxy routes**

Each route proxies requests to the orchestrator API (`http://orchestrator:8001/api/v1/...`), adding the `X-API-KEY` header from environment.

**Step 2: Commit**

```bash
git add dashboard/src/app/api/
git commit -m "feat(dashboard): add API proxy routes for orchestrator"
```

---

## Task 14: Dashboard Integration Test

**Files:**
- Modify: existing e2e test files or create new ones

**Step 1: Verify build**

```bash
cd dashboard && npm run build
```

Ensure no TypeScript errors, all imports resolve, pages render.

**Step 2: Commit any fixes**

```bash
git add dashboard/
git commit -m "test(dashboard): verify build passes with all new pages and components"
```

---

## Worker Stage Counts Reference

For rendering the pipeline grid, hardcode stage counts per worker:

```typescript
export const WORKER_STAGE_COUNTS: Record<string, number> = {
  info_gathering: 10,
  config_mgmt: 11,
  identity_mgmt: 5,
  authentication: 10,
  authorization: 4,
  session_mgmt: 9,
  input_validation: 15,
  error_handling: 2,
  cryptography: 4,
  business_logic: 9,
  client_side: 13,
  chain_worker: 4,
  reporting: 1,
};
```
