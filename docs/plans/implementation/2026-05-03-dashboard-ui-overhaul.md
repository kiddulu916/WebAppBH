# Dashboard UI/UX Overhaul — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove legacy pipeline UI, build accurate 18-worker pipeline with infrastructure shelf, restyle all components to NEONHIVE tokens, simplify the C2 page, and fix campaign detail pages.

**Architecture:** Delete legacy C2 components (PhasePipeline, WorkerGrid, c2/WorkerCard, StatusBoard, WorkerFeed, WorkerConsole). Update `pipeline/` components with the canonical 18-worker layout including an infrastructure shelf. Rename all `WSTG_*` exports to plain names. Sweep every component for raw Tailwind colors and replace with NEONHIVE CSS variable tokens. Simplify the C2 page from 9 widgets to 5 sections. Wire campaign detail pages to `lib/api.ts`.

**Tech Stack:** Next.js 16, React 19, Zustand 5, Tailwind CSS v4, TanStack Table

**Design doc:** `docs/plans/design/2026-05-03-dashboard-ui-overhaul-design.md`

---

## Task 1: Delete Legacy C2 Components

**Files:**
- Delete: `dashboard/src/components/c2/PhasePipeline.tsx`
- Delete: `dashboard/src/components/c2/WorkerGrid.tsx`
- Delete: `dashboard/src/components/c2/WorkerCard.tsx`
- Delete: `dashboard/src/components/c2/StatusBoard.tsx`
- Delete: `dashboard/src/components/c2/WorkerFeed.tsx`
- Delete: `dashboard/src/components/c2/WorkerConsole.tsx`
- Modify: `dashboard/src/app/campaign/c2/page.tsx`

**Step 1: Remove WorkerGrid import and usage from C2 page**

In `dashboard/src/app/campaign/c2/page.tsx`:
- Remove line 6: `import WorkerGrid from "@/components/c2/WorkerGrid";`
- Remove the `SplitConsole` and `WorkerGrid` usage in the main content grid (lines 376-401). Replace with just the Asset Tree on the left and the live event feed area on the right (this will be finalized in Task 5).

For now, replace the WorkerGrid/SplitConsole section with a placeholder:

```tsx
{/* Right -- Event feed (placeholder until Task 5) */}
<div className="col-span-2" data-testid="c2-worker-grid">
  <div className="rounded-lg border border-border bg-bg-secondary p-4">
    <div className="section-label mb-3">EVENTS</div>
    <div className="text-sm text-text-muted">Event feed — see live terminal below</div>
  </div>
</div>
```

Also remove:
- `import SplitConsole from "@/components/c2/SplitConsole";` (line 12)
- The `splitView` state and its toggle button
- The `SplitConsole` conditional rendering

**Step 2: Delete the 6 legacy component files**

```bash
cd dashboard
rm src/components/c2/PhasePipeline.tsx
rm src/components/c2/WorkerGrid.tsx
rm src/components/c2/WorkerCard.tsx
rm src/components/c2/StatusBoard.tsx
rm src/components/c2/WorkerFeed.tsx
rm src/components/c2/WorkerConsole.tsx
```

**Step 3: Verify no broken imports**

```bash
cd dashboard && npx next build 2>&1 | head -40
```

Expected: Build succeeds (no remaining imports of deleted files).

**Step 4: Commit**

```bash
git add -A dashboard/src/components/c2/ dashboard/src/app/campaign/c2/page.tsx
git commit -m "chore(dashboard): delete legacy C2 pipeline components

Remove PhasePipeline, WorkerGrid, c2/WorkerCard, StatusBoard,
WorkerFeed, WorkerConsole. These used fake phase names and are
replaced by the pipeline/ components."
```

---

## Task 2: Rename WSTG Exports and Update Worker List in Types

**Files:**
- Modify: `dashboard/src/types/schema.ts`
- Rename: `dashboard/src/lib/wstg-stages.ts` → `dashboard/src/lib/worker-stages.ts`
- Modify: `dashboard/src/app/campaign/c2/page.tsx`
- Modify: `dashboard/src/app/campaign/[id]/overview/page.tsx`
- Modify: `dashboard/src/app/campaign/[id]/targets/[targetId]/page.tsx`

**Step 1: Update `types/schema.ts` — rename exports and add 5 new workers**

Replace the comment on line 216:
```
// Pipeline / Worker State (WSTG-based)
```
with:
```
// Pipeline / Worker State
```

Replace `WSTG_WORKER_NAMES` (lines 246-260) with:
```typescript
export const INFRA_WORKER_NAMES = [
  "proxy",
  "callback",
  "sandbox_worker",
] as const;

export const PIPELINE_WORKER_NAMES = [
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
  "mobile_worker",
  "reasoning_worker",
  "chain_worker",
  "reporting",
] as const;

export const ALL_WORKER_NAMES = [...INFRA_WORKER_NAMES, ...PIPELINE_WORKER_NAMES] as const;

export type WorkerName = (typeof ALL_WORKER_NAMES)[number];
```

Delete line 262: `export type WSTGWorkerName = ...`

Replace `WORKER_STAGE_COUNTS` (lines 264-278) with:
```typescript
export const WORKER_STAGE_COUNTS: Record<string, number> = {
  proxy: 0,
  callback: 0,
  sandbox_worker: 0,
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
  mobile_worker: 8,
  reasoning_worker: 3,
  chain_worker: 4,
  reporting: 1,
};
```

Replace `WORKER_DEPENDENCIES` (lines 280-294) with:
```typescript
export const WORKER_DEPENDENCIES: Record<string, string[]> = {
  proxy: [],
  callback: [],
  sandbox_worker: [],
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
  mobile_worker: ["authorization", "session_mgmt", "input_validation"],
  reasoning_worker: ["error_handling", "cryptography", "business_logic", "client_side", "mobile_worker"],
  chain_worker: ["reasoning_worker"],
  reporting: ["chain_worker"],
};
```

**Step 2: Rename `wstg-stages.ts` → `worker-stages.ts` and update contents**

```bash
cd dashboard && mv src/lib/wstg-stages.ts src/lib/worker-stages.ts
```

In the new `worker-stages.ts`:
- Replace the comment `WSTG stage definitions` → `Stage definitions for each worker.`
- Rename `export const WSTG_STAGES` → `export const WORKER_STAGES`
- Add entries for the 5 new workers at the end:

```typescript
  mobile_worker: [
    { id: "1", name: "App Discovery", sectionId: "MOBILE-01" },
    { id: "2", name: "Static Analysis", sectionId: "MOBILE-02" },
    { id: "3", name: "Network Analysis", sectionId: "MOBILE-03" },
    { id: "4", name: "API Interception", sectionId: "MOBILE-04" },
    { id: "5", name: "Data Storage", sectionId: "MOBILE-05" },
    { id: "6", name: "Authentication Testing", sectionId: "MOBILE-06" },
    { id: "7", name: "Runtime Analysis", sectionId: "MOBILE-07" },
    { id: "8", name: "Platform Checks", sectionId: "MOBILE-08" },
  ],
  reasoning_worker: [
    { id: "1", name: "Finding Correlation", sectionId: "REASON-01" },
    { id: "2", name: "Impact Analysis", sectionId: "REASON-02" },
    { id: "3", name: "Chain Hypothesis", sectionId: "REASON-03" },
  ],
  proxy: [],
  callback: [],
  sandbox_worker: [],
```

**Step 3: Update all imports of `WSTG_STAGES` and `wstg-stages`**

In `dashboard/src/app/campaign/c2/page.tsx` (line 11):
```
- import { WSTG_STAGES } from "@/lib/wstg-stages";
+ import { WORKER_STAGES } from "@/lib/worker-stages";
```
And update usage on line 434: `WSTG_STAGES[selectedWorker]` → `WORKER_STAGES[selectedWorker]`

In `dashboard/src/app/campaign/[id]/overview/page.tsx` (line 11):
```
- import { WSTG_STAGES } from "@/lib/wstg-stages";
+ import { WORKER_STAGES } from "@/lib/worker-stages";
```
And update usage on line 128: `WSTG_STAGES[selectedWorker]` → `WORKER_STAGES[selectedWorker]`

In `dashboard/src/app/campaign/[id]/targets/[targetId]/page.tsx`:
- Delete the entire inline `WSTG_STAGES` constant (lines 19-143)
- Add import: `import { WORKER_STAGES } from "@/lib/worker-stages";`
- Update usage on line 206: `WSTG_STAGES[selectedWorker]` → `WORKER_STAGES[selectedWorker]`

**Step 4: Remove "WSTG" from UI labels**

In `dashboard/src/app/campaign/c2/page.tsx`:
- Line 369: `WSTG PIPELINE` → `PIPELINE`

**Step 5: Verify no remaining WSTG references**

```bash
grep -r "WSTG\|wstg" dashboard/src/ --include="*.ts" --include="*.tsx" | grep -v node_modules
```

Expected: Only `sectionId` values like `"WSTG-INFO-01"` remain (these are standard identifiers in the stage data, not UI labels). No variable names, imports, comments, or labels should contain WSTG.

**Step 6: Build check**

```bash
cd dashboard && npx next build 2>&1 | head -40
```

**Step 7: Commit**

```bash
git add dashboard/src/types/schema.ts dashboard/src/lib/worker-stages.ts dashboard/src/app/campaign/
git rm dashboard/src/lib/wstg-stages.ts
git commit -m "refactor(dashboard): rename WSTG exports, add 5 new workers

Rename WSTG_WORKER_NAMES → INFRA/PIPELINE/ALL_WORKER_NAMES.
Add proxy, callback, sandbox_worker, mobile_worker, reasoning_worker.
Rename wstg-stages.ts → worker-stages.ts, WSTG_STAGES → WORKER_STAGES.
Remove inline WSTG_STAGES duplicate from target detail page.
Remove 'WSTG' string from all UI labels."
```

---

## Task 3: Rebuild PipelineGrid with Infrastructure Shelf

**Files:**
- Modify: `dashboard/src/components/pipeline/PipelineGrid.tsx`
- Modify: `dashboard/src/components/pipeline/WorkerCard.tsx`

**Step 1: Update WorkerCard with `isInfra` variant**

Replace the full `WorkerCard` component in `dashboard/src/components/pipeline/WorkerCard.tsx`:

```tsx
import { useMemo } from "react";
import type { PipelineWorkerState } from "@/types/schema";

interface WorkerCardProps {
  worker: string;
  state: PipelineWorkerState;
  totalStages: number;
  dependencies?: string[];
  isInfra?: boolean;
  onClick?: () => void;
}

const STATUS_COLORS: Record<string, string> = {
  pending: "border-border bg-bg-tertiary",
  queued: "border-neon-blue/30 bg-neon-blue-glow",
  running: "border-neon-orange/30 bg-neon-orange-glow",
  complete: "border-neon-green/30 bg-neon-green-glow",
  failed: "border-danger/30 bg-danger/10",
  skipped: "border-border bg-bg-surface border-dashed opacity-60",
};

const STATUS_TEXT_COLORS: Record<string, string> = {
  pending: "text-text-muted",
  queued: "text-neon-blue",
  running: "text-neon-orange",
  complete: "text-neon-green",
  failed: "text-danger",
  skipped: "text-text-muted",
};

export default function WorkerCard({ worker, state, totalStages, isInfra, onClick }: WorkerCardProps) {
  const currentStage = state.current_stage_index ?? 0;
  const progressPercent = totalStages > 0 ? Math.min((currentStage / totalStages) * 100, 100) : 0;

  const statusLabel = useMemo(() => {
    if (state.skipped) return "Skipped";
    return state.status.charAt(0).toUpperCase() + state.status.slice(1);
  }, [state.status, state.skipped]);

  const runningAnimation = isInfra
    ? state.status === "running" ? "animate-pulse-green" : ""
    : state.status === "running" ? "animate-pulse-orange" : "";

  if (isInfra) {
    return (
      <button
        onClick={onClick}
        className={`w-36 rounded-lg border p-2 text-left transition-all hover:scale-105 ${STATUS_COLORS[state.status] || STATUS_COLORS.pending} ${runningAnimation}`}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-text-primary capitalize">
            {worker.replace(/_/g, " ")}
          </span>
          <span className={`text-[10px] font-medium ${STATUS_TEXT_COLORS[state.status] || STATUS_TEXT_COLORS.pending}`}>
            {statusLabel}
          </span>
        </div>
      </button>
    );
  }

  return (
    <button
      onClick={onClick}
      className={`w-48 rounded-lg border-2 p-3 text-left transition-all hover:scale-105 ${STATUS_COLORS[state.status] || STATUS_COLORS.pending} ${runningAnimation}`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold text-text-primary capitalize">
          {worker.replace(/_/g, " ")}
        </span>
        <span className={`text-xs font-medium ${STATUS_TEXT_COLORS[state.status] || STATUS_TEXT_COLORS.pending}`}>
          {statusLabel}
        </span>
      </div>

      <div className="mb-1">
        <div className="h-1.5 w-full rounded-full bg-bg-tertiary overflow-hidden">
          <div
            className="h-full rounded-full bg-accent transition-all"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      <div className="text-xs text-text-secondary">
        {currentStage}/{totalStages} stages
      </div>

      {state.last_tool_executed && (
        <div className="mt-1 text-xs text-text-secondary truncate">
          Last: {state.last_tool_executed}
        </div>
      )}

      {state.error && (
        <div className="mt-1 text-xs text-danger truncate">
          {state.error}
        </div>
      )}

      {state.skip_reason && (
        <div className="mt-1 text-xs text-text-muted italic">
          {state.skip_reason}
        </div>
      )}
    </button>
  );
}
```

**Step 2: Update PipelineGrid with infrastructure shelf and 18-worker layout**

Replace the full `PipelineGrid` component in `dashboard/src/components/pipeline/PipelineGrid.tsx`:

```tsx
import { useMemo } from "react";
import WorkerCard from "./WorkerCard";
import type { PipelineWorkerState } from "@/types/schema";
import { WORKER_STAGE_COUNTS, WORKER_DEPENDENCIES, INFRA_WORKER_NAMES } from "@/types/schema";

interface PipelineGridProps {
  workerStates: Record<string, PipelineWorkerState>;
  onWorkerClick?: (worker: string) => void;
}

export default function PipelineGrid({ workerStates, onWorkerClick }: PipelineGridProps) {
  const infraWorkers = useMemo(() => [...INFRA_WORKER_NAMES], []);

  const rows = useMemo(() => [
    ["info_gathering", "config_mgmt", "identity_mgmt", "authentication"],
    ["authorization", "session_mgmt", "input_validation"],
    ["error_handling", "cryptography", "business_logic", "client_side", "mobile_worker"],
    ["reasoning_worker", "chain_worker"],
    ["reporting"],
  ], []);

  return (
    <div className="space-y-4">
      {/* Infrastructure shelf */}
      <div className="rounded-lg border border-dashed border-border-accent bg-bg-tertiary/50 p-3">
        <div className="section-label mb-2">INFRASTRUCTURE</div>
        <div className="flex gap-3 justify-center">
          {infraWorkers.map((worker) => {
            const state = workerStates[worker] || { status: "pending" };
            return (
              <WorkerCard
                key={worker}
                worker={worker}
                state={state}
                totalStages={0}
                isInfra
                onClick={() => onWorkerClick?.(worker)}
              />
            );
          })}
        </div>
      </div>

      {/* Pipeline rows */}
      {rows.map((row, rowIdx) => (
        <div key={rowIdx} className="flex gap-4 items-center justify-center">
          {row.map((worker) => {
            const state = workerStates[worker] || { status: "pending" };
            const totalStages = WORKER_STAGE_COUNTS[worker] || 0;
            return (
              <WorkerCard
                key={worker}
                worker={worker}
                state={state}
                totalStages={totalStages}
                dependencies={WORKER_DEPENDENCIES[worker] || []}
                onClick={() => onWorkerClick?.(worker)}
              />
            );
          })}
        </div>
      ))}
    </div>
  );
}
```

**Step 3: Build check**

```bash
cd dashboard && npx next build 2>&1 | head -40
```

**Step 4: Commit**

```bash
git add dashboard/src/components/pipeline/
git commit -m "feat(dashboard): rebuild PipelineGrid with 18 workers + infra shelf

Add infrastructure shelf (proxy, callback, sandbox_worker) with compact
cards. Add mobile_worker to Row 3, reasoning_worker to Row 4.
WorkerCard gets isInfra variant: no progress bar, green pulse."
```

---

## Task 4: NEONHIVE Restyle — Findings Components

**Files:**
- Modify: `dashboard/src/components/findings/FindingsTable.tsx`
- Modify: `dashboard/src/components/findings/FindingDetail.tsx`

**Step 1: Replace SEVERITY_COLORS in FindingsTable.tsx (line 22-28)**

Replace:
```typescript
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-blue-500/20 text-blue-400",
  info: "bg-gray-500/20 text-gray-400",
};
```

With:
```typescript
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-sev-critical/20 text-sev-critical",
  high: "bg-sev-high/20 text-sev-high",
  medium: "bg-sev-medium/20 text-sev-medium",
  low: "bg-sev-low/20 text-sev-low",
  info: "bg-bg-surface text-text-muted",
};
```

**Step 2: Replace severityColors in FindingDetail.tsx (line 12-18)**

Replace:
```typescript
const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};
```

With:
```typescript
const severityColors: Record<string, string> = {
  critical: "bg-sev-critical/20 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/20 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/20 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/20 text-sev-low border-sev-low/30",
  info: "bg-bg-surface text-text-muted border-border",
};
```

**Step 3: Replace raw colors for Confirmed/FP badges in FindingDetail.tsx**

Line 38-39: Replace `bg-green-500/20 text-green-400` → `bg-neon-green-glow text-neon-green`
Line 42-43: Replace `bg-red-500/20 text-red-400` → `bg-danger/20 text-danger`

**Step 4: Replace button colors in FindingDetail.tsx**

Line 63: Replace `bg-accent-primary text-white hover:bg-accent-primary/90` → `btn-launch`

**Step 5: Commit**

```bash
git add dashboard/src/components/findings/
git commit -m "style(dashboard): restyle findings components with NEONHIVE tokens

Replace raw Tailwind severity colors with --sev-* CSS variables.
Use NEONHIVE token classes for badges and buttons."
```

---

## Task 5: NEONHIVE Restyle — Target, Chain, Resource, Terminal Components

**Files:**
- Modify: `dashboard/src/components/targets/TargetRow.tsx`
- Modify: `dashboard/src/components/targets/TargetTree.tsx`
- Modify: `dashboard/src/components/chains/ChainList.tsx`
- Modify: `dashboard/src/components/chains/ChainDetail.tsx`
- Modify: `dashboard/src/components/resource/ResourceIndicator.tsx`
- Modify: `dashboard/src/components/resource/ResourcePanel.tsx`
- Modify: `dashboard/src/components/terminal/LiveTerminal.tsx`

**Step 1: TargetRow.tsx — replace status colors (lines 11-17)**

Replace:
```typescript
const statusColor =
  target.status === "complete"
    ? "text-green-400"
    : target.status === "running"
      ? "text-amber-400"
      : target.status === "queued"
        ? "text-blue-400"
        : "text-gray-400";
```

With:
```typescript
const statusColor =
  target.status === "complete"
    ? "text-neon-green"
    : target.status === "running"
      ? "text-neon-orange"
      : target.status === "queued"
        ? "text-neon-blue"
        : "text-text-muted";
```

**Step 2: TargetTree.tsx — same replacement (lines 11-18)**

Apply the exact same `text-green-400` → `text-neon-green`, `text-amber-400` → `text-neon-orange`, `text-blue-400` → `text-neon-blue`, `text-gray-400` → `text-text-muted` replacement.

**Step 3: ChainList.tsx — replace SEVERITY_COLORS (lines 9-15)**

Replace:
```typescript
const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-gray-400",
};
```

With:
```typescript
const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-text-muted",
};
```

**Step 4: ChainDetail.tsx — replace SEVERITY_COLORS (lines 10-16)**

Replace:
```typescript
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};
```

With:
```typescript
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-sev-critical/20 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/20 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/20 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/20 text-sev-low border-sev-low/30",
  info: "bg-bg-surface text-text-muted border-border",
};
```

**Step 5: ResourceIndicator.tsx — replace TIER_COLORS (lines 11-16)**

Replace:
```typescript
const TIER_COLORS: Record<string, string> = {
  green: "bg-green-500",
  yellow: "bg-yellow-500",
  red: "bg-red-500",
  critical: "bg-black border border-red-500",
};
```

With:
```typescript
const TIER_COLORS: Record<string, string> = {
  green: "bg-neon-green",
  yellow: "bg-warning",
  red: "bg-danger",
  critical: "bg-bg-void border border-danger",
};
```

Also line 42: Replace `bg-gray-500 animate-pulse` → `bg-text-muted animate-pulse`

**Step 6: ResourcePanel.tsx — replace TIER_COLORS (lines 12-17) and ProgressBar colors (line 20)**

Replace TIER_COLORS:
```typescript
const TIER_COLORS: Record<string, string> = {
  green: "text-neon-green",
  yellow: "text-warning",
  red: "text-danger",
  critical: "text-danger font-bold",
};
```

Replace ProgressBar color logic (line 20):
```typescript
const color = percent > 90 ? "bg-danger" : percent > 70 ? "bg-warning" : "bg-neon-green";
```

Replace threshold label colors (lines 104, 110, 116):
- `text-green-400` → `text-neon-green`
- `text-yellow-400` → `text-warning`
- `text-red-400` → `text-danger`

Replace button colors (lines 128, 143):
- `text-accent-primary` → `text-accent`
- `bg-accent-primary` → `bg-accent`
- `hover:bg-accent-primary/90` → `hover:bg-accent-hover`

**Step 7: LiveTerminal.tsx — replace EVENT_COLORS (lines 13-22)**

Replace:
```typescript
const EVENT_COLORS: Record<string, string> = {
  worker_started: "text-white",
  worker_complete: "text-green-400",
  worker_failed: "text-red-400",
  stage_started: "text-gray-400",
  stage_complete: "text-gray-400",
  finding: "text-yellow-400",
  finding_critical: "text-red-400 font-bold",
  finding_high: "text-yellow-400",
  escalated_access: "text-red-400 font-bold",
  target_expanded: "text-blue-400",
  resource_tier_change: "text-yellow-400",
};
```

With:
```typescript
const EVENT_COLORS: Record<string, string> = {
  worker_started: "text-text-primary",
  worker_complete: "text-neon-green",
  worker_failed: "text-danger",
  stage_started: "text-text-muted",
  stage_complete: "text-text-muted",
  finding: "text-warning",
  finding_critical: "text-danger font-bold",
  finding_high: "text-warning",
  escalated_access: "text-danger font-bold",
  target_expanded: "text-neon-blue",
  resource_tier_change: "text-warning",
};
```

**Step 8: Commit**

```bash
git add dashboard/src/components/targets/ dashboard/src/components/chains/ dashboard/src/components/resource/ dashboard/src/components/terminal/
git commit -m "style(dashboard): restyle target, chain, resource, terminal with NEONHIVE

Replace all raw Tailwind colors (green-400, red-400, amber-400, etc.)
with NEONHIVE token classes (neon-green, danger, neon-orange, etc.)."
```

---

## Task 6: NEONHIVE Restyle — Campaign Pages

**Files:**
- Modify: `dashboard/src/app/campaign/[id]/layout.tsx`
- Modify: `dashboard/src/app/campaign/[id]/overview/page.tsx`
- Modify: `dashboard/src/app/campaign/new/page.tsx`

**Step 1: Campaign layout — replace status badge colors (lines 60-68)**

Replace:
```typescript
activeCampaign.status === "running"
  ? "bg-amber-500/20 text-amber-400"
  : activeCampaign.status === "complete"
    ? "bg-green-500/20 text-green-400"
    : "bg-gray-500/20 text-gray-400"
```

With:
```typescript
activeCampaign.status === "running"
  ? "bg-neon-orange-glow text-neon-orange"
  : activeCampaign.status === "complete"
    ? "bg-neon-green-glow text-neon-green"
    : "bg-bg-surface text-text-muted"
```

Also replace `border-accent-primary text-accent-primary` (line 85) → `border-accent text-accent`

**Step 2: Campaign overview — replace status badge colors (lines 63-72)**

The full status conditional should use NEONHIVE tokens:
```typescript
campaign.status === "running"
  ? "bg-neon-orange-glow text-neon-orange"
  : campaign.status === "complete"
    ? "bg-neon-green-glow text-neon-green"
    : campaign.status === "paused"
      ? "bg-warning/20 text-warning"
      : campaign.status === "cancelled"
        ? "bg-danger/20 text-danger"
        : "bg-bg-surface text-text-muted"
```

These already look correct from the earlier v2 plan execution. Verify and fix if needed.

**Step 3: Campaign new page — replace button/input styling**

In `dashboard/src/app/campaign/new/page.tsx`:
- All `focus:border-accent-primary` → `input-focus` class (remove inline focus styles, add `input-focus` class)
- Line 179: `text-red-400 hover:text-red-300` → `text-danger hover:text-danger/80`
- Line 209: `text-red-400 hover:text-red-300` → `text-danger hover:text-danger/80`
- Line 241: `text-red-400 hover:text-red-300` → `text-danger hover:text-danger/80`
- Line 187, 192, etc: `text-accent-primary` → `text-accent`
- Line 380: `bg-accent-primary ... hover:bg-accent-primary/90` → add `btn-launch` class

**Step 4: Build check**

```bash
cd dashboard && npx next build 2>&1 | head -40
```

**Step 5: Commit**

```bash
git add dashboard/src/app/campaign/
git commit -m "style(dashboard): restyle campaign pages with NEONHIVE tokens

Replace accent-primary with accent, raw color classes with tokens.
Apply input-focus and btn-launch classes to forms and CTAs."
```

---

## Task 7: Simplify C2 Page Layout

**Files:**
- Modify: `dashboard/src/app/campaign/c2/page.tsx`

**Step 1: Remove WorkerHealthPanel import and usage**

Remove:
- Line 14: `import WorkerHealthPanel from "@/components/c2/WorkerHealthPanel";`
- Lines ~403-404: `<WorkerHealthPanel />`

**Step 2: Remove split view toggle state and button**

Remove:
- `const [splitView, setSplitView] = useState(false);` (already removed in Task 1 if done correctly)
- The split view toggle `<button>` in the header

**Step 3: Reorganize the remaining layout**

The final C2 page structure should be (top to bottom):

```tsx
<div className="space-y-5">
  {/* 1. Page header */}
  {/* (keep as-is: domain badge, rerun, settings) */}

  {/* 2. Infrastructure shelf + Pipeline grid */}
  <div data-testid="c2-phase-pipeline" className="rounded-lg border border-border bg-bg-secondary p-4">
    <div className="section-label mb-3">PIPELINE</div>
    <PipelineGrid
      workerStates={jobsToWorkerStates(jobs)}
      onWorkerClick={setSelectedWorker}
    />
  </div>

  {/* 3. Asset Tree (1/3) + Event area (2/3) */}
  <div className="grid grid-cols-3 gap-5">
    <div className="col-span-1" data-testid="c2-asset-tree">
      {/* (keep Asset Tree as-is) */}
    </div>
    <div className="col-span-2">
      <div className="rounded-lg border border-border bg-bg-secondary p-4">
        <div className="section-label mb-3">CAMPAIGN TIMELINE</div>
        <CampaignTimeline jobs={jobs} />
      </div>
    </div>
  </div>

  {/* 4. System Pulse (1/2) + Queue Health (1/2) */}
  <div className="grid grid-cols-2 gap-5">
    <SystemPulse />
    <QueueHealthWidget />
  </div>

  {/* 5. Diff Timeline (1/2) + Scope Drift Alerts (1/2) */}
  <div className="grid grid-cols-2 gap-5">
    <DiffTimeline events={events} />
    <ScopeDriftAlerts events={events} />
  </div>

  {/* Drawers (unchanged) */}
  <AssetDetailDrawer ... />
  {selectedWorker && <WorkerDetailDrawer ... />}
  <SettingsDrawer ... />
</div>
```

**Step 4: Build check**

```bash
cd dashboard && npx next build 2>&1 | head -40
```

**Step 5: Commit**

```bash
git add dashboard/src/app/campaign/c2/page.tsx
git commit -m "refactor(dashboard): simplify C2 page from 9 widgets to 5 sections

Remove WorkerHealthPanel (redundant with pipeline grid), WorkerGrid
(deleted), SplitConsole. Reorganize: pipeline, asset tree + timeline,
system pulse + queue health, diff timeline + scope alerts."
```

---

## Task 8: Wire Campaign Detail Pages to `lib/api.ts`

**Files:**
- Modify: `dashboard/src/app/campaign/[id]/targets/page.tsx`
- Modify: `dashboard/src/app/campaign/[id]/findings/page.tsx`
- Modify: `dashboard/src/app/campaign/[id]/chains/page.tsx`
- Modify: `dashboard/src/app/campaign/[id]/findings/[vulnId]/page.tsx`
- Modify: `dashboard/src/app/campaign/[id]/chains/[chainId]/page.tsx`

Currently these pages use raw `fetch()` calls to `/api/campaigns/${id}/...` (a Next.js API route that may not exist). They should use the `api` object from `lib/api.ts` which hits the orchestrator directly.

**Step 1: Update targets page**

In `dashboard/src/app/campaign/[id]/targets/page.tsx`, replace the fetch block with:

```typescript
import { api } from "@/lib/api";

// In useEffect:
const data = await api.getTargets();
setTargets(data.targets.map(t => ({
  id: t.id,
  domain: t.base_domain,
  target_type: "seed" as const,
  priority: 0,
  status: t.status || "pending",
  wildcard: false,
  wildcard_count: null,
  parent_target_id: null,
  worker_states: {},
  vulnerability_count: t.vuln_count || 0,
})));
```

**Step 2: Update findings page**

In `dashboard/src/app/campaign/[id]/findings/page.tsx`, replace fetch with:

```typescript
import { api } from "@/lib/api";

// In useEffect — get findings by fetching vulnerabilities for all targets in campaign:
const targetsRes = await api.getTargets();
const allFindings: Finding[] = [];
for (const target of targetsRes.targets) {
  const vulnRes = await api.getVulnerabilities(target.id);
  for (const v of vulnRes.vulnerabilities) {
    allFindings.push({
      id: v.id,
      target_id: v.target_id,
      severity: v.severity as VulnSeverity,
      title: v.title,
      vuln_type: v.severity,
      section_id: null,
      worker_type: null,
      stage_name: null,
      source_tool: v.source_tool,
      confirmed: false,
      false_positive: false,
      description: v.description,
      evidence: null,
      remediation: null,
      created_at: v.created_at || "",
      target_domain: v.asset_value || undefined,
    });
  }
}
setFindings(allFindings);
```

**Step 3: Update chains page**

In `dashboard/src/app/campaign/[id]/chains/page.tsx`, replace fetch with:

```typescript
import { api } from "@/lib/api";

// In useEffect — get attack paths (chains) for targets in campaign:
const targetsRes = await api.getTargets();
const allChains: ChainFindingView[] = [];
for (const target of targetsRes.targets) {
  try {
    const pathsRes = await api.getAttackPaths(target.id);
    for (const path of pathsRes.paths) {
      allChains.push({
        id: path.id,
        target_id: target.id,
        chain_description: path.description,
        severity: path.severity,
        total_impact: null,
        linked_vulnerability_ids: path.steps.map(s => s.vuln_id),
        created_at: new Date().toISOString(),
      });
    }
  } catch {
    // target may not have attack paths
  }
}
setChains(allChains);
```

**Step 4: Update finding detail page**

In `dashboard/src/app/campaign/[id]/findings/[vulnId]/page.tsx`, the raw fetch calls should use the orchestrator API via `api.getVulnerabilities()` or a direct fetch to the orchestrator. Since there's no single-vuln endpoint in `api.ts`, add one:

In `dashboard/src/lib/api.ts`, add:
```typescript
getVulnerability(vulnId: number) {
  return request<import("@/types/schema").Vulnerability>(`/api/v1/vulnerabilities/${vulnId}`);
},
```

Then update the page to use it.

**Step 5: Update chain detail page similarly**

The chain detail page already fetches from `/api/campaigns/${campaignId}/chains/${chainId}`. Update to use the orchestrator.

**Step 6: Build check**

```bash
cd dashboard && npx next build 2>&1 | head -40
```

**Step 7: Commit**

```bash
git add dashboard/src/app/campaign/ dashboard/src/lib/api.ts
git commit -m "fix(dashboard): wire campaign detail pages to orchestrator API

Replace raw fetch() calls to /api/campaigns/ with lib/api.ts methods
that hit the orchestrator directly. Add getVulnerability() to api."
```

---

## Task 9: Final Audit — Raw Tailwind Color Sweep

**Files:** Any remaining files with raw Tailwind colors

**Step 1: Search for remaining raw color classes**

```bash
grep -rn "text-gray-\|text-red-\|text-green-\|text-blue-\|text-amber-\|text-yellow-\|text-orange-\|bg-gray-\|bg-red-\|bg-green-\|bg-blue-\|bg-amber-\|bg-yellow-\|bg-orange-\|border-gray-\|border-red-\|border-green-\|border-blue-" dashboard/src/ --include="*.tsx" --include="*.ts" | grep -v node_modules | grep -v ".css"
```

**Step 2: Fix any remaining occurrences**

Apply the standard mapping:
- `text-gray-*` → `text-text-muted` or `text-text-secondary`
- `text-red-*` → `text-danger`
- `text-green-*` → `text-neon-green`
- `text-blue-*` → `text-neon-blue`
- `text-amber-*` / `text-orange-*` → `text-neon-orange`
- `text-yellow-*` → `text-warning`
- `bg-gray-*` → `bg-bg-surface` or `bg-bg-tertiary`
- `bg-red-*` → `bg-danger/*`
- `bg-green-*` → `bg-neon-green-glow`
- `bg-blue-*` → `bg-neon-blue-glow`
- `bg-amber-*` / `bg-orange-*` → `bg-neon-orange-glow`
- `border-gray-*` → `border-border`
- `accent-primary` → `accent`

**Step 3: Full build check**

```bash
cd dashboard && npx next build
```

Expected: Clean build with zero errors.

**Step 4: Commit**

```bash
git add dashboard/src/
git commit -m "style(dashboard): final NEONHIVE restyle sweep

Remove all remaining raw Tailwind color classes, replace with
NEONHIVE CSS variable tokens for full design system consistency."
```

---

## Execution Order

Tasks must be done in this sequence:
1. **Task 1** (delete legacy) — clears the noise
2. **Task 2** (rename WSTG, update worker list) — unblocks pipeline work
3. **Task 3** (rebuild PipelineGrid) — core pipeline fix
4. **Tasks 4-6** (NEONHIVE restyle) — can be done in parallel
5. **Task 7** (simplify C2) — depends on Tasks 1-3
6. **Task 8** (wire detail pages) — independent of styling tasks
7. **Task 9** (final audit) — must be last
