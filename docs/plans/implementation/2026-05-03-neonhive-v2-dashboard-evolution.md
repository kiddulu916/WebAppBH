# NEONHIVE v2 Dashboard Evolution — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the broken pipeline UI, unify the two competing store/type systems, wire new backend data (campaigns, worker health, WSTG stages) into the dashboard, and evolve NEONHIVE with micro-interactions.

**Architecture:** Merge the newer `campaign.ts` types + `pipelineStore.ts` + `campaignStore.ts` into the existing `campaign.ts` store and `schema.ts` types. Replace the old flat `PhasePipeline` (wrong phase names) with the WSTG-aware `PipelineGrid` (correct worker names + dependency graph). Add campaign CRUD to orchestrator. Apply NEONHIVE design tokens to all pipeline components.

**Tech Stack:** Next.js 16, React 19, Zustand 5, Tailwind v4, FastAPI, SQLAlchemy (async)

---

## Task 1: Unify Types — Merge `types/campaign.ts` into `types/schema.ts`

**Files:**
- Modify: `dashboard/src/types/schema.ts`
- Delete: `dashboard/src/types/campaign.ts`

**Step 1: Add campaign + pipeline types to schema.ts**

Add these types to the end of `dashboard/src/types/schema.ts`:

```typescript
// ---------------------------------------------------------------------------
// Campaign
// ---------------------------------------------------------------------------

export type CampaignStatus = "pending" | "running" | "paused" | "complete" | "cancelled";

export interface Campaign extends Timestamps {
  id: number;
  name: string;
  description: string | null;
  status: CampaignStatus;
  scope_config: {
    in_scope: string[];
    out_of_scope: string[];
  } | null;
  rate_limit: number;
  has_credentials: boolean;
  started_at: string | null;
  completed_at: string | null;
}

// ---------------------------------------------------------------------------
// Pipeline / Worker State (WSTG-based)
// ---------------------------------------------------------------------------

export type PipelineWorkerStatus = "pending" | "queued" | "running" | "complete" | "failed" | "skipped";

export interface PipelineWorkerState {
  status: PipelineWorkerStatus;
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

export interface ResourceStatus {
  tier: "green" | "yellow" | "red" | "critical";
  cpu_percent: number;
  memory_percent: number;
  active_workers: number;
}

export const WSTG_WORKER_NAMES = [
  "info_gathering",
  "config_mgmt",
  "identity_mgmt",
  "authentication",
  "authorization",
  "session_mgmt",
  "input_validation",
  "error_handling",
  "cryptography",
  "business_logic",
  "client_side",
  "chain_worker",
  "reporting",
] as const;

export type WSTGWorkerName = typeof WSTG_WORKER_NAMES[number];

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

export const WORKER_DEPENDENCIES: Record<string, string[]> = {
  info_gathering: [],
  config_mgmt: ["info_gathering"],
  identity_mgmt: ["config_mgmt"],
  authentication: ["identity_mgmt"],
  authorization: ["authentication"],
  session_mgmt: ["authentication"],
  input_validation: ["authentication"],
  error_handling: ["authorization", "session_mgmt", "input_validation"],
  cryptography: ["authorization", "session_mgmt", "input_validation"],
  business_logic: ["authorization", "session_mgmt", "input_validation"],
  client_side: ["authorization", "session_mgmt", "input_validation"],
  chain_worker: ["error_handling", "cryptography", "business_logic", "client_side"],
  reporting: ["chain_worker"],
};
```

**Step 2: Delete `dashboard/src/types/campaign.ts`**

**Step 3: Update `dashboard/src/types/index.ts` if it re-exports from campaign.ts**

**Step 4: Verify no build errors**

Run: `cd dashboard && npx next build 2>&1 | head -30`
Expected: Import errors in files still referencing `@/types/campaign` — these will be fixed in Task 2.

---

## Task 2: Unify Stores — Merge pipeline + campaign stores into `stores/campaign.ts`

**Files:**
- Modify: `dashboard/src/stores/campaign.ts`
- Delete: `dashboard/src/stores/campaignStore.ts`
- Delete: `dashboard/src/stores/pipelineStore.ts`

**Step 1: Add pipeline state to the existing campaign store**

Add to `CampaignState` interface in `dashboard/src/stores/campaign.ts`:

```typescript
  /* pipeline */
  workerStates: Record<string, PipelineWorkerState>;
  activeCampaign: Campaign | null;

  /* pipeline actions */
  setWorkerStates: (states: Record<string, PipelineWorkerState>) => void;
  updateWorkerState: (worker: string, update: Partial<PipelineWorkerState>) => void;
  setActiveCampaign: (campaign: Campaign | null) => void;
```

Add the implementations in the `create()` call:

```typescript
  workerStates: {},
  activeCampaign: null,

  setWorkerStates: (states) => set({ workerStates: states }),
  updateWorkerState: (worker, update) =>
    set((s) => ({
      workerStates: {
        ...s.workerStates,
        [worker]: { ...s.workerStates[worker], ...update },
      },
    })),
  setActiveCampaign: (campaign) => set({ activeCampaign: campaign }),
```

Import `Campaign` and `PipelineWorkerState` from `@/types/schema`.

**Step 2: Delete `dashboard/src/stores/campaignStore.ts` and `dashboard/src/stores/pipelineStore.ts`**

**Step 3: Update all imports**

Files that import from deleted stores need updating:
- `dashboard/src/app/campaign/[id]/overview/page.tsx` — change to `@/stores/campaign`
- Any other `[id]` pages that reference `pipelineStore` or `campaignStore`

Search: `grep -r "campaignStore\|pipelineStore" dashboard/src/`

---

## Task 3: Add Campaign CRUD Endpoints to Orchestrator

**Files:**
- Modify: `orchestrator/main.py`

**Step 1: Add campaign endpoints after the targets section**

```python
# ── Campaigns ──────────────────────────────────────────────

@app.post("/api/v1/campaigns", status_code=201)
async def create_campaign(body: dict):
    async with get_session() as session:
        campaign = Campaign(
            name=body["name"],
            description=body.get("description"),
            status="pending",
            scope_config=body.get("scope_config"),
            rate_limit=body.get("rate_limit", 50),
            has_credentials=body.get("has_credentials", False),
        )
        session.add(campaign)
        await session.flush()
        return {"id": campaign.id, "name": campaign.name, "status": campaign.status}


@app.get("/api/v1/campaigns")
async def list_campaigns():
    async with get_session() as session:
        rows = (await session.execute(
            select(Campaign).order_by(Campaign.created_at.desc())
        )).scalars().all()
        return {"campaigns": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "status": c.status,
                "scope_config": c.scope_config,
                "rate_limit": c.rate_limit,
                "has_credentials": c.has_credentials,
                "started_at": c.started_at.isoformat() if c.started_at else None,
                "completed_at": c.completed_at.isoformat() if c.completed_at else None,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "target_count": len(c.targets) if c.targets else 0,
            }
            for c in rows
        ]}


@app.get("/api/v1/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int):
    async with get_session() as session:
        campaign = await session.get(Campaign, campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")
        return {
            "id": campaign.id,
            "name": campaign.name,
            "description": campaign.description,
            "status": campaign.status,
            "scope_config": campaign.scope_config,
            "rate_limit": campaign.rate_limit,
            "has_credentials": campaign.has_credentials,
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
            "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
            "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        }


@app.patch("/api/v1/campaigns/{campaign_id}")
async def update_campaign(campaign_id: int, body: dict):
    async with get_session() as session:
        campaign = await session.get(Campaign, campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")
        for field in ("name", "description", "status", "scope_config", "rate_limit", "has_credentials"):
            if field in body:
                setattr(campaign, field, body[field])
        await session.flush()
        return {"id": campaign.id, "status": campaign.status}
```

**Step 2: Add `Campaign` to the imports at the top of main.py**

Ensure `from lib_webbh import ..., Campaign` is in the imports.

---

## Task 4: Add Campaign API Methods to `lib/api.ts`

**Files:**
- Modify: `dashboard/src/lib/api.ts`

**Step 1: Add campaign methods to the `api` object**

```typescript
  /* ---- Campaigns ---- */

  getCampaigns() {
    return request<{ campaigns: import("@/types/schema").Campaign[] }>("/api/v1/campaigns");
  },

  getCampaign(id: number) {
    return request<import("@/types/schema").Campaign>(`/api/v1/campaigns/${id}`);
  },

  createCampaign(data: { name: string; description?: string; scope_config?: unknown; rate_limit?: number; has_credentials?: boolean }) {
    return request<{ id: number; name: string; status: string }>("/api/v1/campaigns", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  updateCampaign(id: number, data: { name?: string; description?: string; status?: string }) {
    return request<{ id: number; status: string }>(`/api/v1/campaigns/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },
```

---

## Task 5: Restyle Pipeline Components with NEONHIVE Tokens

**Files:**
- Modify: `dashboard/src/components/pipeline/PipelineGrid.tsx`
- Modify: `dashboard/src/components/pipeline/WorkerCard.tsx`
- Modify: `dashboard/src/components/pipeline/WorkerDetailDrawer.tsx`

**Step 1: Update WorkerCard to use NEONHIVE colors**

Replace raw Tailwind colors with CSS variable classes:

| Old | New |
|-----|-----|
| `border-gray-600 bg-bg-surface` | `border-border bg-bg-tertiary` |
| `border-blue-500 bg-blue-500/10` | `border-neon-blue/30 bg-neon-blue-glow` |
| `border-amber-500 bg-amber-500/10` | `border-neon-orange/30 bg-neon-orange-glow` |
| `border-green-500 bg-green-500/10` | `border-neon-green/30 bg-neon-green-glow` |
| `border-red-500 bg-red-500/10` | `border-danger/30 bg-danger/10` |
| `text-gray-400` | `text-text-muted` |
| `text-blue-400` | `text-neon-blue` |
| `text-amber-400` | `text-neon-orange` |
| `text-green-400` | `text-neon-green` |
| `text-red-400` | `text-danger` |
| `bg-bg-void` (progress track) | `bg-bg-tertiary` |
| `bg-accent-primary` (progress fill) | `bg-accent` |

Add running animation: `animate-pulse-orange` for running state (instead of generic `animate-pulse`).

Update imports: `from "@/types/campaign"` → `from "@/types/schema"`.

**Step 2: Update PipelineGrid**

- Update imports from `@/types/campaign` → `@/types/schema`
- Use `WORKER_STAGE_COUNTS` and `WORKER_DEPENDENCIES` from `@/types/schema`
- Add connecting lines between rows using CSS pseudo-elements or SVG arrows

**Step 3: Update WorkerDetailDrawer**

Replace raw Tailwind colors:
- `bg-green-500/10 text-green-400` → `bg-neon-green-glow text-neon-green`
- `bg-amber-500/10 text-amber-400` → `bg-neon-orange-glow text-neon-orange`
- `bg-bg-void text-gray-500` → `bg-bg-tertiary text-text-muted`
- `bg-red-500/10 border border-red-500/30` → `bg-danger/10 border border-danger/30`
- `text-red-400` → `text-danger`
- `bg-gray-500/10 border border-gray-500/30` → `bg-bg-surface border border-border`

Update imports from `@/types/campaign` → `@/types/schema`.
Add `animate-slide-right` to the drawer entrance.

---

## Task 6: Integrate PipelineGrid into C2 Page

**Files:**
- Modify: `dashboard/src/app/campaign/c2/page.tsx`

**Step 1: Replace PhasePipeline with PipelineGrid**

Remove the old `PhasePipeline` import and component. Add:

```typescript
import PipelineGrid from "@/components/pipeline/PipelineGrid";
import WorkerDetailDrawer from "@/components/pipeline/WorkerDetailDrawer";
import { WORKER_STAGE_COUNTS } from "@/types/schema";
import type { PipelineWorkerState } from "@/types/schema";
```

**Step 2: Add job-to-worker-state mapping function**

Convert `JobState[]` from the API into `Record<string, PipelineWorkerState>`:

```typescript
function jobsToWorkerStates(jobs: JobState[]): Record<string, PipelineWorkerState> {
  const states: Record<string, PipelineWorkerState> = {};
  for (const job of jobs) {
    // Container name like "webbh-info-gathering-t1" → "info_gathering"
    const workerKey = job.container_name
      .replace(/^webbh-/, "")
      .replace(/-t\d+$/, "")
      .replace(/-/g, "_");

    const status = (() => {
      switch (job.status) {
        case "RUNNING": return "running" as const;
        case "QUEUED": return "queued" as const;
        case "COMPLETED": return "complete" as const;
        case "FAILED": return "failed" as const;
        case "PAUSED": return "running" as const; // show as running with paused indicator
        default: return "pending" as const;
      }
    })();

    // If multiple jobs map to same worker, prefer the most active one
    const existing = states[workerKey];
    if (!existing || statusPriority(status) > statusPriority(existing.status)) {
      states[workerKey] = {
        status,
        current_section_id: job.current_phase ?? undefined,
        last_tool_executed: job.last_tool_executed ?? undefined,
        started_at: job.started_at ?? undefined,
        completed_at: job.completed_at ?? undefined,
        total_stages: WORKER_STAGE_COUNTS[workerKey] ?? 0,
      };
    }
  }
  return states;
}

function statusPriority(s: string): number {
  switch (s) {
    case "running": return 4;
    case "queued": return 3;
    case "failed": return 2;
    case "complete": return 1;
    default: return 0;
  }
}
```

**Step 3: Add selectedWorker state and WSTG_STAGES lookup**

Move the `WSTG_STAGES` constant from `campaign/[id]/overview/page.tsx` into a shared file at `dashboard/src/lib/wstg-stages.ts` so both pages can use it.

**Step 4: Replace the PhasePipeline section in the JSX**

```tsx
{/* Pipeline Grid */}
<div data-testid="c2-phase-pipeline" className="rounded-lg border border-border bg-bg-secondary p-4">
  <div className="section-label mb-3">WSTG PIPELINE</div>
  <PipelineGrid
    workerStates={jobsToWorkerStates(jobs)}
    onWorkerClick={setSelectedWorker}
  />
</div>

{/* Worker Detail Drawer */}
{selectedWorker && (
  <WorkerDetailDrawer
    worker={selectedWorker}
    state={jobsToWorkerStates(jobs)[selectedWorker] || { status: "pending" }}
    stages={WSTG_STAGES[selectedWorker] || []}
    findingCount={0}
    onClose={() => setSelectedWorker(null)}
  />
)}
```

**Step 5: Add selectedWorker state variable**

```typescript
const [selectedWorker, setSelectedWorker] = useState<string | null>(null);
```

---

## Task 7: Wire `[id]/overview` Page to Real API

**Files:**
- Modify: `dashboard/src/app/campaign/[id]/overview/page.tsx`

**Step 1: Replace the broken `/api/campaigns/${id}` fetch with `api.getCampaign()`**

```typescript
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Campaign, PipelineWorkerState } from "@/types/schema";
import { WORKER_STAGE_COUNTS } from "@/types/schema";
```

Replace the `useEffect` fetch block:
```typescript
useEffect(() => {
  const fetchCampaign = async () => {
    try {
      const data = await api.getCampaign(Number(campaignId));
      setCampaign(data);
      setActiveCampaign(data);
    } catch {
      // handled by api.request()
    } finally {
      setLoading(false);
    }
  };
  fetchCampaign();
}, [campaignId, setActiveCampaign]);
```

**Step 2: Update store references**

Replace `usePipelineStore` with `useCampaignStore`:
```typescript
const workerStates = useCampaignStore((s) => s.workerStates);
const setActiveCampaign = useCampaignStore((s) => s.setActiveCampaign);
```

**Step 3: Remove WSTG_STAGES from this file** (moved to shared `lib/wstg-stages.ts` in Task 6)

**Step 4: Apply NEONHIVE tokens to status badges**

Replace raw Tailwind colors:
- `bg-amber-500/20 text-amber-400` → `bg-neon-orange-glow text-neon-orange`
- `bg-green-500/20 text-green-400` → `bg-neon-green-glow text-neon-green`
- `bg-yellow-500/20 text-yellow-400` → `bg-warning/20 text-warning`
- `bg-red-500/20 text-red-400` → `bg-danger/20 text-danger`
- `bg-gray-500/20 text-gray-400` → `bg-bg-surface text-text-muted`
- `bg-blue-500/20 text-blue-400` → `bg-neon-blue-glow text-neon-blue`
- `text-2xl font-bold text-amber-400` → `text-2xl font-bold text-neon-orange`
- `text-2xl font-bold text-red-400` → `text-2xl font-bold text-danger`
- `text-2xl font-bold text-gray-400` → `text-2xl font-bold text-text-muted`

---

## Task 8: Add Worker Health Panel to C2 Console

**Files:**
- Modify: `dashboard/src/app/campaign/c2/page.tsx`

**Step 1: Import and add WorkerHealthPanel**

```typescript
import WorkerHealthPanel from "@/components/c2/WorkerHealthPanel";
```

Add between the Worker Grid and System Pulse sections:

```tsx
{/* Worker Health */}
<WorkerHealthPanel />
```

This component already exists and is already styled with NEONHIVE tokens.

---

## Task 9: Add NEONHIVE v2 Micro-interactions to globals.css

**Files:**
- Modify: `dashboard/src/app/globals.css`

**Step 1: Add glitch text animation**

```css
@keyframes glitch {
  0%, 100% { clip-path: inset(0 0 0 0); transform: none; }
  20% { clip-path: inset(20% 0 60% 0); transform: translateX(-2px); }
  40% { clip-path: inset(60% 0 10% 0); transform: translateX(2px); }
  60% { clip-path: inset(40% 0 30% 0); transform: translateX(-1px); }
}
.animate-glitch { animation: glitch 0.3s ease-out; }
```

**Step 2: Add scanline hover effect for cards**

```css
.card-scanline {
  position: relative;
  overflow: hidden;
}
.card-scanline::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: repeating-linear-gradient(
    0deg, transparent, transparent 2px,
    rgba(0, 232, 123, 0.04) 2px, rgba(0, 232, 123, 0.04) 4px
  );
  opacity: 0;
  transition: opacity 0.2s ease;
}
.card-scanline:hover::before { opacity: 1; }
```

**Step 3: Add holographic border for campaign cards**

```css
@property --holo-angle {
  syntax: "<angle>";
  initial-value: 0deg;
  inherits: false;
}

@keyframes holo-rotate {
  to { --holo-angle: 360deg; }
}

.card-holo {
  border: 1px solid transparent;
  background:
    linear-gradient(var(--bg-secondary), var(--bg-secondary)) padding-box,
    conic-gradient(from var(--holo-angle), var(--neon-orange), var(--neon-green), var(--neon-blue), var(--neon-orange)) border-box;
  animation: holo-rotate 4s linear infinite;
}
```

**Step 4: Add data stream effect for live counters**

```css
@keyframes data-rain {
  from { background-position: 0 0; }
  to { background-position: 0 20px; }
}

.live-data-stream {
  background-image: linear-gradient(
    180deg,
    transparent 50%,
    rgba(0, 232, 123, 0.03) 50%
  );
  background-size: 100% 4px;
  animation: data-rain 0.5s linear infinite;
}
```

---

## Task 10: Extract WSTG Stages to Shared File

**Files:**
- Create: `dashboard/src/lib/wstg-stages.ts`

Move the `WSTG_STAGES` constant from `campaign/[id]/overview/page.tsx` to this shared file so both the C2 page and the overview page can import it.

```typescript
export const WSTG_STAGES: Record<string, { id: string; name: string; sectionId: string }[]> = {
  // ... (full content from overview page)
};
```

---

## Task 11: Clean Up Deleted Files & Verify Build

**Files:**
- Verify all imports resolved
- Run build

**Step 1: Search for stale imports**

```bash
grep -r "from.*types/campaign" dashboard/src/ --include="*.ts" --include="*.tsx"
grep -r "from.*stores/campaignStore\|from.*stores/pipelineStore" dashboard/src/ --include="*.ts" --include="*.tsx"
```

Fix any remaining references.

**Step 2: Build check**

```bash
cd dashboard && npx next build
```

Expected: Clean build with no errors.

---

## Execution Order

Tasks must be done in this sequence:
1. Task 1 (types) → Task 2 (stores) → these unblock everything
2. Task 10 (extract WSTG stages) → used by Task 6 and Task 7
3. Task 3 (orchestrator endpoints) → Task 4 (api client) → these unblock Task 7
4. Task 5 (restyle pipeline) → Task 6 (integrate into C2) → these fix the pipeline
5. Task 7 (wire [id] overview) → depends on Tasks 2, 3, 4, 5
6. Task 8 (worker health) → independent, can be done anytime after Task 6
7. Task 9 (CSS micro-interactions) → independent, can be done anytime
8. Task 11 (cleanup + verify) → must be last
