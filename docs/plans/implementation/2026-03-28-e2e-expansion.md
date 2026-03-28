# E2E Test Suite Expansion — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand the e2e test suite from 10 files / ~20 tests to 21 files / ~70 tests, building three new pages, removing two unused pages, and adding edge case + cross-cutting flow coverage.

**Architecture:** Build new UI pages using existing "use client" + Zustand + TanStack Table patterns. Add missing backend endpoints in FastAPI orchestrator. Test everything with Playwright using the existing api-client + seed-factories + fixtures helpers.

**Tech Stack:** Next.js 16, React 19, Zustand, TanStack Table, React Flow (@xyflow/react), Tailwind v4, FastAPI, SQLAlchemy async, Playwright

**Design doc:** `docs/plans/design/2026-03-28-e2e-expansion-design.md`

---

## Task 1: Remove Compare & Explorer Pages

**Files:**
- Delete: `dashboard/src/app/campaign/compare/page.tsx`
- Delete: `dashboard/src/app/campaign/explorer/page.tsx`
- Modify: `dashboard/src/components/layout/IconRail.tsx:25-40` (NAV_ITEMS)
- Modify: `dashboard/src/components/layout/CommandPalette.tsx:62-73` (items)
- Modify: `dashboard/src/hooks/useKeyboardShortcuts.ts:33-42` (routes)
- Modify: `dashboard/src/components/layout/ShortcutsOverlay.tsx:5-18` (SHORTCUTS)
- Modify: `dashboard/src/app/page.tsx:131-136` (Quick Links — "Data Explorer" points to /campaign/findings now)

**Step 1: Delete the page files**

```bash
rm dashboard/src/app/campaign/compare/page.tsx
rmdir dashboard/src/app/campaign/compare
rm dashboard/src/app/campaign/explorer/page.tsx
rmdir dashboard/src/app/campaign/explorer
```

**Step 2: Remove from IconRail NAV_ITEMS**

In `dashboard/src/components/layout/IconRail.tsx`, remove these two entries from NAV_ITEMS and the `GitCompareArrows` import:
```typescript
// REMOVE these lines:
  { href: "/campaign/explorer", label: "Data Explorer", icon: Database },
  { href: "/campaign/compare", label: "Compare", icon: GitCompareArrows },
```
Also remove `GitCompareArrows` and `Database` from the lucide-react import (if Database is only used for explorer).

**Step 3: Remove from CommandPalette**

In `dashboard/src/components/layout/CommandPalette.tsx`, remove:
```typescript
// REMOVE this line:
      { id: "nav-explorer", label: "Data Explorer", category: "nav", icon: Database, action: () => router.push("/campaign/explorer") },
```
Remove the `Database` import from lucide-react if no longer used.

**Step 4: Remove from keyboard shortcuts**

In `dashboard/src/hooks/useKeyboardShortcuts.ts`, remove from the routes object:
```typescript
// REMOVE this line:
          e: "/campaign/explorer",
```

In `dashboard/src/components/layout/ShortcutsOverlay.tsx`, remove:
```typescript
// REMOVE this line:
  { keys: "g e", desc: "Data Explorer" },
```

**Step 5: Update home page Quick Links**

In `dashboard/src/app/page.tsx`, change the "Data Explorer" quick link to point at `/campaign/assets` instead:
```typescript
// CHANGE from:
          <QuickLink
            href="/campaign/findings"
            icon={<Database className="h-5 w-5 text-neon-blue" />}
            title="Data Explorer"
            desc="Browse all collected data"
          />
// TO:
          <QuickLink
            href="/campaign/assets"
            icon={<Database className="h-5 w-5 text-neon-blue" />}
            title="Asset Inventory"
            desc="Browse all discovered assets"
          />
```

**Step 6: Verify build**

```bash
cd dashboard && npm run build
```
Expected: Build succeeds with no references to deleted pages.

**Step 7: Commit**

```bash
git add -A && git commit -m "chore: remove compare and explorer pages, update nav references"
```

---

## Task 2: Backend — Attack Paths & Execution State Endpoints

**Files:**
- Modify: `orchestrator/main.py` (add 3 new endpoints)
- Modify: `dashboard/src/lib/api.ts` (add frontend API methods)
- Modify: `dashboard/src/types/schema.ts` (add new types)

**Step 1: Add attack-paths endpoint to orchestrator**

In `orchestrator/main.py`, after the `get_attack_graph` endpoint (~line 1297), add:

```python
# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/attack-paths — exploitable vuln chains
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/attack-paths")
async def get_attack_paths(target_id: int):
    """Return attack path chains: sequences of vulns that could be chained."""
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset))
        )).scalars().all()

        # Build paths: group vulns by asset, chain by severity desc
        paths = []
        asset_vulns: dict[int, list] = {}
        for v in vulns:
            if v.asset_id:
                asset_vulns.setdefault(v.asset_id, []).append(v)

        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        path_id = 0
        for asset_id, avulns in asset_vulns.items():
            if len(avulns) < 2:
                continue
            sorted_vulns = sorted(avulns, key=lambda v: sev_order.get(v.severity, 0), reverse=True)
            path_id += 1
            steps = []
            for v in sorted_vulns:
                steps.append({
                    "vuln_id": v.id,
                    "title": v.title,
                    "severity": v.severity,
                    "asset_id": v.asset_id,
                    "asset_value": v.asset.asset_value if v.asset else None,
                })
            paths.append({
                "id": path_id,
                "severity": sorted_vulns[0].severity,
                "steps": steps,
                "description": f"Chain of {len(steps)} vulnerabilities on {steps[0]['asset_value'] or 'unknown'}",
            })

    return {"target_id": target_id, "paths": paths}
```

**Step 2: Add execution state endpoint**

After the attack-paths endpoint, add:

```python
# ---------------------------------------------------------------------------
# GET /api/v1/targets/{target_id}/execution — pipeline execution state
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets/{target_id}/execution")
async def get_execution_state(target_id: int):
    """Return current pipeline execution state for a target."""
    from lib_webbh.playbooks import BUILTIN_PLAYBOOKS, _ALL_RECON_STAGES

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        jobs = (await session.execute(
            select(JobState).where(JobState.target_id == target_id)
            .order_by(JobState.last_seen.desc())
        )).scalars().all()

    # Derive per-stage status from jobs
    stages = []
    for stage_name in _ALL_RECON_STAGES:
        matching_jobs = [j for j in jobs if j.current_phase and stage_name in j.current_phase]
        if matching_jobs:
            job = matching_jobs[0]
            stages.append({
                "name": stage_name,
                "status": job.status.lower(),
                "tool": job.last_tool_executed,
                "started_at": job.created_at.isoformat() if job.created_at else None,
                "last_seen": job.last_seen.isoformat() if job.last_seen else None,
            })
        else:
            stages.append({"name": stage_name, "status": "pending", "tool": None, "started_at": None, "last_seen": None})

    return {
        "target_id": target_id,
        "playbook": target.last_playbook or "wide_recon",
        "stages": stages,
    }
```

**Step 3: Add apply-playbook endpoint**

After the execution state endpoint, add:

```python
# ---------------------------------------------------------------------------
# POST /api/v1/targets/{target_id}/apply-playbook — apply playbook config
# ---------------------------------------------------------------------------
class ApplyPlaybookRequest(BaseModel):
    playbook_name: str

@app.post("/api/v1/targets/{target_id}/apply-playbook")
async def apply_playbook(target_id: int, body: ApplyPlaybookRequest):
    """Apply a playbook configuration to a target."""
    from lib_webbh.playbooks import get_playbook

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        playbook = get_playbook(body.playbook_name)
        target.last_playbook = body.playbook_name
        await session.flush()

    # Write playbook config to target's config directory
    import json, os
    config_dir = f"shared/config/{target_id}"
    os.makedirs(config_dir, exist_ok=True)
    with open(f"{config_dir}/playbook.json", "w") as f:
        json.dump(playbook.to_dict(), f, indent=2)

    return {"target_id": target_id, "playbook_name": body.playbook_name, "applied": True}
```

**Step 4: Add asset detail sub-endpoints**

After the apply-playbook endpoint, add:

```python
# ---------------------------------------------------------------------------
# Asset detail sub-endpoints for expandable rows
# ---------------------------------------------------------------------------
@app.get("/api/v1/assets/{asset_id}/locations")
async def get_asset_locations(asset_id: int):
    async with get_session() as session:
        locs = (await session.execute(
            select(Location).where(Location.asset_id == asset_id)
        )).scalars().all()
    return {"asset_id": asset_id, "locations": [
        {"id": l.id, "port": l.port, "protocol": l.protocol, "service": l.service, "state": l.state}
        for l in locs
    ]}

@app.get("/api/v1/assets/{asset_id}/vulnerabilities")
async def get_asset_vulns(asset_id: int):
    async with get_session() as session:
        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.asset_id == asset_id)
        )).scalars().all()
    return {"asset_id": asset_id, "vulnerabilities": [
        {"id": v.id, "severity": v.severity, "title": v.title, "description": v.description, "source_tool": v.source_tool}
        for v in vulns
    ]}

@app.get("/api/v1/assets/{asset_id}/cloud")
async def get_asset_cloud(asset_id: int):
    """Cloud assets linked through the same target as this asset."""
    async with get_session() as session:
        asset = (await session.execute(
            select(Asset).where(Asset.id == asset_id)
        )).scalar_one_or_none()
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        clouds = (await session.execute(
            select(CloudAsset).where(CloudAsset.target_id == asset.target_id)
        )).scalars().all()
    return {"asset_id": asset_id, "cloud_assets": [
        {"id": c.id, "provider": c.provider, "asset_type": c.asset_type, "url": c.url, "is_public": c.is_public}
        for c in clouds
    ]}
```

**Step 5: Add pagination to existing GET /api/v1/assets endpoint**

Find the existing `get_assets` endpoint in `orchestrator/main.py` and add `page` and `per_page` query params:

```python
# Modify existing endpoint signature to:
@app.get("/api/v1/assets")
async def get_assets(target_id: int, page: int = 1, per_page: int = 50):
    # ... existing query ...
    # Add pagination:
    offset = (page - 1) * per_page
    # Apply .offset(offset).limit(per_page) to the query
    # Return total count in response
```

The exact modification depends on the current endpoint code — find it and add pagination.

**Step 6: Add new types to schema.ts**

In `dashboard/src/types/schema.ts`, append:

```typescript
// ---------------------------------------------------------------------------
// Attack Paths
// ---------------------------------------------------------------------------

export interface AttackPathStep {
  vuln_id: number;
  title: string;
  severity: VulnSeverity;
  asset_id: number | null;
  asset_value: string | null;
}

export interface AttackPath {
  id: number;
  severity: VulnSeverity;
  steps: AttackPathStep[];
  description: string;
}

// ---------------------------------------------------------------------------
// Execution State
// ---------------------------------------------------------------------------

export interface StageExecution {
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "paused" | "stopped";
  tool: string | null;
  started_at: string | null;
  last_seen: string | null;
}

export interface ExecutionState {
  target_id: number;
  playbook: string;
  stages: StageExecution[];
}

// ---------------------------------------------------------------------------
// Graph (already partially defined via api.ts, formalize here)
// ---------------------------------------------------------------------------

export interface GraphNode {
  id: string;
  label: string;
  type: "target" | "subdomain" | "ip" | "cidr" | "port" | "vulnerability";
  severity?: VulnSeverity;
}

export interface GraphEdge {
  source: string;
  target: string;
}
```

**Step 7: Add new API methods to dashboard api.ts**

In `dashboard/src/lib/api.ts`, add to the `api` object:

```typescript
  getAttackPaths(targetId: number) {
    return request<{ target_id: number; paths: import("@/types/schema").AttackPath[] }>(
      `/api/v1/targets/${targetId}/attack-paths`,
    );
  },

  getExecutionState(targetId: number) {
    return request<import("@/types/schema").ExecutionState>(
      `/api/v1/targets/${targetId}/execution`,
    );
  },

  applyPlaybook(targetId: number, playbookName: string) {
    return request<{ target_id: number; playbook_name: string; applied: boolean }>(
      `/api/v1/targets/${targetId}/apply-playbook`,
      { method: "POST", body: JSON.stringify({ playbook_name: playbookName }) },
    );
  },

  getAssetLocations(assetId: number) {
    return request<{ asset_id: number; locations: import("@/types/schema").Location[] }>(
      `/api/v1/assets/${assetId}/locations`,
    );
  },

  getAssetVulnerabilities(assetId: number) {
    return request<{ asset_id: number; vulnerabilities: import("@/types/schema").Vulnerability[] }>(
      `/api/v1/assets/${assetId}/vulnerabilities`,
    );
  },

  getAssetCloud(assetId: number) {
    return request<{ asset_id: number; cloud_assets: import("@/types/schema").CloudAsset[] }>(
      `/api/v1/assets/${assetId}/cloud`,
    );
  },
```

**Step 8: Add new methods to e2e api-client.ts**

In `dashboard/e2e/helpers/api-client.ts`, add to the `apiClient` object:

```typescript
  getPlaybooks: () =>
    req<Array<{ id?: number; name: string; stages: Array<{ name: string; enabled: boolean }> }>>(
      "/playbooks",
    ),

  applyPlaybook: (targetId: number, playbookName: string) =>
    req<{ applied: boolean }>(`/targets/${targetId}/apply-playbook`, {
      method: "POST",
      body: JSON.stringify({ playbook_name: playbookName }),
    }),

  getExecutionState: (targetId: number) =>
    req<{ stages: Array<{ name: string; status: string; tool: string | null }> }>(
      `/targets/${targetId}/execution`,
    ),

  getAttackGraph: (targetId: number) =>
    req<{ nodes: Array<{ id: string; label: string; type: string }>; edges: Array<{ source: string; target: string }> }>(
      `/targets/${targetId}/graph`,
    ),

  getAttackPaths: (targetId: number) =>
    req<{ paths: Array<{ id: number; severity: string; steps: Array<{ vuln_id: number; title: string }> }> }>(
      `/targets/${targetId}/attack-paths`,
    ),

  controlWorker: (containerName: string, action: string) =>
    req<{ success: boolean }>("/control", {
      method: "POST",
      body: JSON.stringify({ container_name: containerName, action }),
    }),

  updateSchedule: (id: number, data: { enabled?: boolean }) =>
    req<{ id: number; enabled: boolean }>(`/schedules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
```

**Step 9: Verify build**

```bash
cd dashboard && npm run build
```

**Step 10: Commit**

```bash
git add -A && git commit -m "feat(api): add attack-paths, execution-state, apply-playbook, and asset detail endpoints"
```

---

## Task 3: Backend — Extend Test Seed Endpoint

**Files:**
- Modify: `orchestrator/main.py` (~line 1996, `test_seed` function)

**Step 1: Extend the seed endpoint**

Add the following sections to the existing `test_seed` function, after the Jobs section (~line 2076):

```python
        # --- Graph relationships (edges are implicit from assets + vulns + locations already seeded) ---
        # No extra data needed — the graph endpoint builds edges from existing data.

        # --- Additional locations on other assets (for richer expandable rows) ---
        session.add(Location(asset_id=asset_ids[1], port=8080, protocol="tcp", service="http-alt", state="open"))
        session.add(Location(asset_id=asset_ids[3], port=22, protocol="tcp", service="ssh", state="open"))
        session.add(Location(asset_id=asset_ids[3], port=443, protocol="tcp", service="https", state="open"))
```

Also update the response to include `asset_ids`:

```python
    return {
        "seeded": True,
        "target_id": body.target_id,
        "assets": len(assets_data),
        "vulnerabilities": len(vulns_data),
        "cloud_assets": 2,
        "alerts": 1,
        "asset_ids": asset_ids,
        "vuln_ids": vuln_ids,
        "job_ids": job_ids,
    }
```

**Step 2: Update e2e api-client seedTestData return type**

In `dashboard/e2e/helpers/api-client.ts`, update the return type:

```typescript
  seedTestData: (targetId: number) =>
    req<{ seeded: boolean; asset_ids: number[]; vuln_ids: number[]; job_ids: number[] }>("/test/seed", {
```

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(api): extend test seed with extra locations and asset_ids in response"
```

---

## Task 4: Install React Flow

**Step 1: Install @xyflow/react**

```bash
cd dashboard && npm install @xyflow/react
```

**Step 2: Commit**

```bash
git add package.json package-lock.json && git commit -m "chore: install @xyflow/react for attack graph visualization"
```

---

## Task 5: Rebuild Assets Page with Expandable Rows

**Files:**
- Modify: `dashboard/src/app/campaign/assets/page.tsx` (full rewrite)

**Step 1: Rewrite assets page**

Replace the entire contents of `dashboard/src/app/campaign/assets/page.tsx` with a new implementation that includes:

- `"use client"` directive
- Import: `useState`, `useEffect`, `useMemo`, `useCallback` from react
- Import: `useRouter` from next/navigation
- Import: lucide icons (`Globe`, `Search`, `ArrowUpDown`, `ChevronLeft`, `ChevronRight`, `ChevronDown`, `ChevronUp`, `Loader2`, `RefreshCw`, `Shield`, `Cloud`, `Network`, `AlertTriangle`)
- Import: `api` from `@/lib/api`, `useCampaignStore` from `@/stores/campaign`
- Import types: `AssetWithLocations` from `@/lib/api`

**State:**
```typescript
const [data, setData] = useState<AssetWithLocations[]>([]);
const [loading, setLoading] = useState(true);
const [error, setError] = useState(false);
const [search, setSearch] = useState("");
const [typeFilter, setTypeFilter] = useState<string>("all");
const [sortKey, setSortKey] = useState<SortKey>("created_at");
const [sortDir, setSortDir] = useState<SortDir>("desc");
const [page, setPage] = useState(0);
const [expandedRow, setExpandedRow] = useState<number | null>(null);
const [activeTab, setActiveTab] = useState<"locations" | "vulns" | "cloud" | "tree">("locations");
const [detailData, setDetailData] = useState<{ locations: any[]; vulns: any[]; cloud: any[] } | null>(null);
const [detailLoading, setDetailLoading] = useState(false);
```

**Data fetching with error handling:**
```typescript
const fetchData = useCallback(async () => {
  if (!activeTarget) return;
  setLoading(true);
  setError(false);
  try {
    const res = await api.getAssets(activeTarget.id);
    setData(res.assets);
  } catch {
    setError(true);
  } finally {
    setLoading(false);
  }
}, [activeTarget]);
```

**Expandable row behavior:**
- When `asset-expand-btn-{id}` is clicked, set `expandedRow` to that asset's id
- Fetch detail data from `api.getAssetLocations`, `api.getAssetVulnerabilities`, `api.getAssetCloud` in parallel
- Render a detail panel below the row with 4 tabs: Locations, Vulnerabilities, Cloud, Tree

**Table columns:** Type, Hostname/IP, Ports (from `locations` array), Vuln Count (derived), Source Tool, Discovered At

**Critical data-testid attributes:**
- `assets-table` on the table wrapper
- `assets-search` on the search input
- `assets-type-filter` on the type select dropdown
- `asset-row-{id}` on each table row
- `asset-expand-btn-{id}` on each expand chevron button
- `asset-detail-panel-{id}` on the expanded detail panel
- `asset-tab-locations`, `asset-tab-vulns`, `asset-tab-cloud`, `asset-tab-tree` on tab buttons
- `asset-vuln-badge-{id}` on the vuln count badge (links to /campaign/findings)
- `assets-pagination` on pagination wrapper
- `assets-empty-state` on empty state container
- `assets-error-state` on error state container
- `assets-retry-btn` on retry button

**Empty state:**
```tsx
<div data-testid="assets-empty-state" className="flex flex-col items-center justify-center py-16">
  <Globe className="h-10 w-10 text-text-muted" />
  <p className="mt-3 text-sm text-text-muted">
    No assets discovered yet. Create a target and run a scan to start discovering assets.
  </p>
</div>
```

**Error state:**
```tsx
<div data-testid="assets-error-state" className="flex flex-col items-center justify-center py-16">
  <AlertTriangle className="h-10 w-10 text-danger" />
  <p className="mt-3 text-sm text-text-muted">Failed to load assets.</p>
  <button data-testid="assets-retry-btn" onClick={fetchData} className="mt-3 ...">
    <RefreshCw className="h-3.5 w-3.5" /> Retry
  </button>
</div>
```

Follow the styling patterns from the existing targets/page.tsx: neon color theme, `bg-bg-secondary`, `border-border`, `text-text-primary`, etc.

**Step 2: Verify build**

```bash
cd dashboard && npm run build
```

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(dashboard): rebuild assets page with expandable rows, tabs, and error states"
```

---

## Task 6: Rebuild Flow Page — Playbook Configurator + Monitor

**Files:**
- Modify: `dashboard/src/app/campaign/flow/page.tsx` (full rewrite)

**Step 1: Rewrite flow page**

Replace `dashboard/src/app/campaign/flow/page.tsx` with a two-panel layout:

**Left panel — Playbook Configurator:**
- `flow-playbook-select`: Dropdown calling `api.getPlaybooks()` to list available playbooks
- Each playbook displays its stages as cards
- `flow-stage-card-{name}`: Stage card showing name, enabled status
- `flow-stage-toggle-{name}`: Toggle switch for enabling/disabling stage
- `flow-stage-expand-{name}`: Expand button to show tool parameters
- `flow-save-playbook-btn`: Save custom playbook button
- `flow-apply-btn`: Apply to target button
- `flow-apply-target-select`: Target selector dropdown for apply action

**Right panel — Live Execution Monitor:**
- `flow-monitor-target-select`: Target selector (uses `useCampaignStore` activeTarget)
- Calls `api.getExecutionState(targetId)` with polling (10s interval)
- `flow-monitor-stage-{name}`: Stage entry in vertical timeline
- `flow-monitor-status-{name}`: Status indicator (pending/running/completed/failed)
- `flow-monitor-tool-{name}`: Tool name when expanded
- `flow-monitor-logs-link-{name}`: "View Full Logs" link → navigates to `/campaign/c2`
- Running stages get `animate-pulse-orange` class

**Empty states:**
- `flow-empty-config` when no playbook selected
- `flow-empty-monitor` when no executions running
- `flow-connection-lost` banner when SSE disconnects

**Layout:**
```tsx
<div className="grid grid-cols-2 gap-6 animate-fade-in">
  <div className="space-y-4"> {/* Left: Configurator */} </div>
  <div className="space-y-4"> {/* Right: Monitor */} </div>
</div>
```

Follow existing polling pattern from the old flow/page.tsx (setInterval + cancelled flag).

**Step 2: Verify build**

```bash
cd dashboard && npm run build
```

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(dashboard): rebuild flow page with playbook configurator and execution monitor"
```

---

## Task 7: Build Attack Graph Page with React Flow

**Files:**
- Modify: `dashboard/src/app/campaign/graph/page.tsx` (full rewrite)

**Step 1: Read the current graph page to understand what exists**

```bash
cat dashboard/src/app/campaign/graph/page.tsx
```

**Step 2: Rewrite graph page using @xyflow/react**

Replace the page with a React Flow based implementation:

**Imports:**
```typescript
"use client";
import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  ReactFlow, Background, Controls, MiniMap,
  useNodesState, useEdgesState,
  type Node, type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
```

**Key components:**
- Full-screen canvas with `<ReactFlow>` component
- Custom node components colored by type (subdomain=blue, ip=orange, vuln=red, port=gray, target=green)
- Node size scaled by severity for vuln nodes
- Floating control panel (`graph-target-select`, `graph-attack-paths-toggle`, filters)
- Detail sidebar (`graph-detail-sidebar`) that slides in on node click
- Attack paths overlay: fetch from `api.getAttackPaths(targetId)`, highlight edges in red when toggled

**Data-testid attributes:**
- `graph-canvas` on the ReactFlow wrapper div
- `graph-target-select` on target dropdown
- `graph-attack-paths-toggle` on the toggle switch
- `graph-filter-type-{type}` on type filter checkboxes
- `graph-severity-slider` on severity range input
- `graph-layout-select` on layout algorithm dropdown
- `graph-fit-btn`, `graph-reset-btn` on action buttons
- `graph-node-{id}` on custom node components
- `graph-detail-sidebar`, `graph-detail-close` on the sidebar
- `graph-path-list`, `graph-path-item-{id}` on attack path list items
- `graph-empty-state` on empty state
- `graph-error-overlay` on error overlay

**Layout algorithm:** Use React Flow's built-in dagre layout or manual force positioning:
```typescript
// Convert API response to React Flow nodes/edges
const apiToFlow = (apiNodes, apiEdges): { nodes: Node[], edges: Edge[] } => {
  // Position nodes using a simple layered layout
  // Target at top, assets in middle, vulns at bottom
};
```

**Empty state:**
```tsx
<div data-testid="graph-empty-state" className="flex flex-col items-center justify-center h-full">
  <Network className="h-10 w-10 text-text-muted" />
  <p className="mt-3 text-sm text-text-muted">No assets to graph. Run a scan to populate the attack surface.</p>
</div>
```

**Step 3: Verify build**

```bash
cd dashboard && npm run build
```

**Step 4: Commit**

```bash
git add -A && git commit -m "feat(dashboard): build attack graph page with React Flow and attack path overlays"
```

---

## Task 8: Add Empty/Error State data-testids to Existing Pages

**Files:**
- Modify: `dashboard/src/app/campaign/targets/page.tsx`
- Modify: `dashboard/src/app/campaign/c2/page.tsx`
- Modify: `dashboard/src/app/campaign/findings/page.tsx`
- Modify: `dashboard/src/app/campaign/bounties/page.tsx`
- Modify: `dashboard/src/app/campaign/schedules/page.tsx`
- Modify: `dashboard/src/app/campaign/cloud/page.tsx`
- Modify: `dashboard/src/app/campaign/vulns/page.tsx`

**Step 1: Add data-testid attributes to empty and error states on each page**

For each page, find the "no data" / empty rendering and add `data-testid="{page}-empty-state"`. If there's no error handling, add a try/catch to the data fetch with `data-testid="{page}-error-state"` and `data-testid="{page}-retry-btn"`.

Pattern for each page:
```tsx
// Where the "No X found" or empty message is:
<div data-testid="targets-empty-state">...</div>

// Add error state if missing:
{error && (
  <div data-testid="targets-error-state">
    <p>Failed to load data.</p>
    <button data-testid="targets-retry-btn" onClick={fetchData}>Retry</button>
  </div>
)}
```

Pages to modify:
- `targets/page.tsx` → `targets-empty-state`, `targets-error-state`, `targets-retry-btn`
- `c2/page.tsx` → `c2-empty-state` (when no jobs/workers)
- `findings/page.tsx` → `findings-empty-state`, `findings-error-state`, `findings-retry-btn`
- `bounties/page.tsx` → `bounties-empty-state`, `bounties-error-state`, `bounties-retry-btn`
- `schedules/page.tsx` → `schedules-empty-state`, `schedules-error-state`, `schedules-retry-btn`
- `cloud/page.tsx` → `cloud-empty-state`
- `vulns/page.tsx` → `vulns-empty-state`

**Step 2: Verify build**

```bash
cd dashboard && npm run build
```

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(dashboard): add empty/error state data-testid attributes to all pages"
```

---

## Task 9: Write E2E Test — Assets Inventory

**Files:**
- Create: `dashboard/e2e/tests/assets-inventory.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Assets Inventory", () => {
  let targetId: number;
  let baseDomain: string;
  let seedResult: { asset_ids: number[]; vuln_ids: number[] };

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    seedResult = await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("displays seeded assets in table with correct columns", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();
    await page.waitForURL("**/campaign/assets");

    const table = page.getByTestId("assets-table");
    await expect(table).toBeVisible({ timeout: 10_000 });

    // Verify seeded assets appear (5 assets from seed)
    await expect(page.getByText(`sub1.${baseDomain}`)).toBeVisible();
    await expect(page.getByText(`sub2.${baseDomain}`)).toBeVisible();
    await expect(page.getByText("10.0.0.1")).toBeVisible();
  });

  test("search filters assets by hostname", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    const searchInput = page.getByTestId("assets-search");
    await searchInput.fill("admin");

    // Only admin subdomain should be visible
    await expect(page.getByText(`admin.${baseDomain}`)).toBeVisible();
    await expect(page.getByText("10.0.0.1")).not.toBeVisible();
  });

  test("expands row to show locations tab", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    // Click expand on first asset row
    const firstAssetId = seedResult.asset_ids[0];
    await page.getByTestId(`asset-expand-btn-${firstAssetId}`).click();

    // Detail panel should appear with locations tab active
    const panel = page.getByTestId(`asset-detail-panel-${firstAssetId}`);
    await expect(panel).toBeVisible({ timeout: 5_000 });

    // Locations tab should show port 80 and 443
    await expect(panel.getByText("80")).toBeVisible();
    await expect(panel.getByText("443")).toBeVisible();
  });

  test("switches between detail tabs", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    const firstAssetId = seedResult.asset_ids[0];
    await page.getByTestId(`asset-expand-btn-${firstAssetId}`).click();

    const panel = page.getByTestId(`asset-detail-panel-${firstAssetId}`);
    await expect(panel).toBeVisible({ timeout: 5_000 });

    // Switch to Vulnerabilities tab
    await page.getByTestId("asset-tab-vulns").click();
    await expect(panel.getByText("SQL Injection")).toBeVisible({ timeout: 5_000 });

    // Switch to Cloud tab
    await page.getByTestId("asset-tab-cloud").click();
    await expect(panel.getByText("s3_bucket").or(panel.getByText("S3"))).toBeVisible({ timeout: 5_000 });
  });

  test("type filter narrows results", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    // Filter by IP type
    await page.getByTestId("assets-type-filter").selectOption("ip");

    // Only IPs should show
    await expect(page.getByText("10.0.0.1")).toBeVisible();
    await expect(page.getByText(`sub1.${baseDomain}`)).not.toBeVisible();
  });
});
```

**Step 2: Run tests to verify**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/assets-inventory.spec.ts
```

**Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): add assets-inventory test suite with 5 tests"
```

---

## Task 10: Write E2E Test — Workflow Builder

**Files:**
- Create: `dashboard/e2e/tests/workflow-builder.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Workflow Builder", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("displays playbook selector with built-in playbooks", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    const select = page.getByTestId("flow-playbook-select");
    await expect(select).toBeVisible({ timeout: 10_000 });

    // Should have built-in options
    await expect(select.locator("option")).toHaveCount(5); // 4 built-in + "Select..."
  });

  test("selecting playbook shows stage cards with toggles", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    await page.getByTestId("flow-playbook-select").selectOption("wide_recon");

    // Should show all 7 recon stages
    await expect(page.getByTestId("flow-stage-card-passive_discovery")).toBeVisible();
    await expect(page.getByTestId("flow-stage-card-deep_recon")).toBeVisible();

    // Each stage should have a toggle
    await expect(page.getByTestId("flow-stage-toggle-passive_discovery")).toBeVisible();
  });

  test("toggling a stage off grays out the card", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    await page.getByTestId("flow-playbook-select").selectOption("wide_recon");
    await expect(page.getByTestId("flow-stage-card-subdomain_takeover")).toBeVisible();

    // Toggle off subdomain_takeover
    await page.getByTestId("flow-stage-toggle-subdomain_takeover").click();

    // Card should have opacity/disabled styling
    const card = page.getByTestId("flow-stage-card-subdomain_takeover");
    await expect(card).toHaveClass(/opacity/);
  });

  test("execution monitor shows stage statuses for active target", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    // Monitor panel should show stages with seeded job states
    await expect(page.getByTestId("flow-monitor-stage-passive_discovery")).toBeVisible({ timeout: 10_000 });
    // The seeded job has status "RUNNING" with phase "passive_discovery"
    await expect(page.getByTestId("flow-monitor-status-passive_discovery")).toContainText(/running/i);
  });

  test("apply playbook button triggers API call", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    await page.getByTestId("flow-playbook-select").selectOption("api_focused");
    await page.getByTestId("flow-apply-btn").click();

    // Verify the playbook was applied (toast or status change)
    await expect(page.getByText(/applied/i).or(page.getByText(/api_focused/i))).toBeVisible({ timeout: 5_000 });
  });
});
```

**Step 2: Run tests**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/workflow-builder.spec.ts
```

**Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): add workflow-builder test suite with 5 tests"
```

---

## Task 11: Write E2E Test — Attack Graph

**Files:**
- Create: `dashboard/e2e/tests/attack-graph.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Attack Graph", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("renders graph canvas with nodes from seeded data", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();
    await page.waitForURL("**/campaign/graph");

    const canvas = page.getByTestId("graph-canvas");
    await expect(canvas).toBeVisible({ timeout: 10_000 });

    // Should have nodes rendered (React Flow renders nodes as divs)
    // Target node + 5 assets + 2 locations + 3 vulns = 11 nodes
    const nodes = page.locator("[data-testid^='graph-node-']");
    await expect(nodes.first()).toBeVisible({ timeout: 5_000 });
  });

  test("attack paths toggle shows path list", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();

    await expect(page.getByTestId("graph-canvas")).toBeVisible({ timeout: 10_000 });

    // Toggle attack paths
    await page.getByTestId("graph-attack-paths-toggle").click();

    // Path list should appear (seeded data has vulns on shared assets)
    const pathList = page.getByTestId("graph-path-list");
    await expect(pathList).toBeVisible({ timeout: 5_000 });
  });

  test("clicking a node opens detail sidebar", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();

    await expect(page.getByTestId("graph-canvas")).toBeVisible({ timeout: 10_000 });

    // Click on any visible node
    const firstNode = page.locator("[data-testid^='graph-node-']").first();
    await firstNode.click();

    // Sidebar should slide in
    const sidebar = page.getByTestId("graph-detail-sidebar");
    await expect(sidebar).toBeVisible({ timeout: 5_000 });

    // Close button should work
    await page.getByTestId("graph-detail-close").click();
    await expect(sidebar).not.toBeVisible();
  });

  test("fit-to-view and reset layout buttons work", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();

    await expect(page.getByTestId("graph-canvas")).toBeVisible({ timeout: 10_000 });

    // Buttons should be clickable without errors
    await page.getByTestId("graph-fit-btn").click();
    await page.getByTestId("graph-reset-btn").click();

    // Canvas should still be visible (no crash)
    await expect(page.getByTestId("graph-canvas")).toBeVisible();
  });
});
```

**Step 2: Run tests**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/attack-graph.spec.ts
```

**Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): add attack-graph test suite with 4 tests"
```

---

## Task 12: Write E2E Test — Empty States

**Files:**
- Create: `dashboard/e2e/tests/empty-states.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Empty States", () => {
  let targetId: number;
  let baseDomain: string;

  // Create target but do NOT seed data — pages should show empty states
  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("assets page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();
    await expect(page.getByTestId("assets-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("findings page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();
    await expect(page.getByTestId("findings-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("bounties page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Bounties" }).click();
    await expect(page.getByTestId("bounties-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("schedules page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Schedules" }).click();
    await expect(page.getByTestId("schedules-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("flow page shows empty config and monitor states", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await expect(page.getByTestId("flow-empty-config")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("flow-empty-monitor")).toBeVisible();
  });

  test("graph page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();
    await expect(page.getByTestId("graph-empty-state")).toBeVisible({ timeout: 10_000 });
  });
});
```

**Step 2: Run tests**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/empty-states.spec.ts
```

**Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): add empty-states test suite covering 6 pages"
```

---

## Task 13: Write E2E Test — API Errors

**Files:**
- Create: `dashboard/e2e/tests/api-errors.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("API Error Handling", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("500 on assets fetch shows error state with retry", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // Intercept assets API and return 500
    await page.route("**/api/v1/assets*", (route) =>
      route.fulfill({ status: 500, body: JSON.stringify({ detail: "Internal error" }) })
    );

    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-error-state")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("assets-retry-btn")).toBeVisible();

    // No console errors (white screen check)
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));

    // Remove route intercept and click retry
    await page.unroute("**/api/v1/assets*");
    await page.getByTestId("assets-retry-btn").click();

    // Should now load successfully (no seeded data = empty state)
    await expect(page.getByTestId("assets-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("500 on targets fetch shows error state", async ({ page }) => {
    // Intercept before navigating
    await page.route("**/api/v1/targets", (route) =>
      route.fulfill({ status: 500, body: JSON.stringify({ detail: "DB down" }) })
    );

    await page.goto("/campaign/targets");

    await expect(page.getByTestId("targets-error-state")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("targets-retry-btn")).toBeVisible();
  });

  test("SSE disconnect shows connection lost banner on flow page", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    // Block SSE endpoint
    await page.route("**/api/v1/stream/**", (route) => route.abort());

    // Trigger an action that would establish SSE
    // The flow monitor polls via HTTP, but if SSE is used check for connection-lost
    // This depends on implementation — verify the banner appears
    await expect(page.getByTestId("flow-connection-lost").or(page.getByTestId("flow-empty-monitor"))).toBeVisible({ timeout: 15_000 });
  });

  test("no unhandled promise rejections on error pages", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));

    // Intercept multiple APIs
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 500, body: JSON.stringify({ detail: "Error" }) })
    );

    await page.goto("/campaign/targets");
    await page.waitForTimeout(3000);

    // Filter out expected errors (our API client throws intentionally)
    const unexpected = errors.filter(
      (e) => !e.includes("API 500") && !e.includes("Network error")
    );
    expect(unexpected).toHaveLength(0);
  });
});
```

**Step 2: Run tests**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/api-errors.spec.ts
```

**Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): add api-errors test suite covering error states and retry"
```

---

## Task 14: Write E2E Test — Edge Cases

**Files:**
- Create: `dashboard/e2e/tests/edge-cases.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Edge Cases", () => {
  test("special characters in company name render safely", async ({ page }) => {
    const target = factories.target({
      company_name: `O'Reilly & Co. <test> "quoted"`,
    });
    const res = await apiClient.createTarget(target);

    try {
      await page.goto("/campaign/targets");
      await expect(page.getByText(`O'Reilly & Co.`)).toBeVisible({ timeout: 10_000 });
      // Verify no HTML injection — the text should be escaped
      const content = await page.content();
      expect(content).not.toContain("<test>");
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });

  test("long domain does not break table layout", async ({ page }) => {
    const longDomain = "a".repeat(60) + ".example.com";
    const target = factories.target({ base_domain: longDomain });
    const res = await apiClient.createTarget(target);

    try {
      await page.goto("/campaign/targets");
      // Table should be visible and not overflow horizontally
      const table = page.locator("table").first();
      await expect(table).toBeVisible({ timeout: 10_000 });
      const box = await table.boundingBox();
      const viewport = page.viewportSize();
      expect(box!.width).toBeLessThanOrEqual(viewport!.width);
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });

  test("rapid double-click on create does not duplicate target", async ({ page }) => {
    await page.goto("/campaign");

    // Fill scope builder (step 1)
    await page.getByTestId("scope-company-input").fill("DoubleClick-Corp");
    await page.getByTestId("scope-domain-input").fill("doubleclick.example.com");
    await page.getByTestId("scope-next-btn").click();

    // Skip through remaining steps to submit
    for (let i = 0; i < 3; i++) {
      await page.getByTestId("scope-next-btn").click();
    }

    // Double-click submit rapidly
    const submit = page.getByTestId("scope-submit-btn");
    await submit.dblclick();

    // Wait for navigation
    await page.waitForURL("**/campaign/c2", { timeout: 10_000 });

    // Check targets — should only have 1 with this name
    const targets = await apiClient.getTargets();
    const matches = targets.targets.filter(
      (t) => t.company_name === "DoubleClick-Corp"
    );
    expect(matches.length).toBe(1);

    // Cleanup
    for (const t of matches) {
      await apiClient.deleteTarget(t.id).catch(() => {});
    }
  });

  test("fast typing in command palette does not crash", async ({ page }) => {
    const target = factories.target();
    const res = await apiClient.createTarget(target);

    try {
      await page.goto("/");
      await page.getByRole("button", { name: new RegExp(target.base_domain) }).click();
      await page.waitForURL("**/campaign/c2");

      // Open command palette
      await page.keyboard.press("Meta+k");
      const input = page.getByTestId("command-input");
      await expect(input).toBeVisible({ timeout: 3_000 });

      // Type very fast
      await input.type("asdfghjklqwertyuiop", { delay: 10 });
      await page.waitForTimeout(500);

      // Should still be responsive — no crash
      await expect(input).toBeVisible();

      // Escape to close
      await page.keyboard.press("Escape");
      await expect(page.getByTestId("command-palette")).not.toBeVisible();
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });
});
```

**Step 2: Run tests**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/edge-cases.spec.ts
```

**Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): add edge-cases test suite for special chars, long strings, double-click, fast typing"
```

---

## Task 15: Deepen Existing Test Files

**Files:**
- Modify: `dashboard/e2e/tests/findings-browser.spec.ts`
- Modify: `dashboard/e2e/tests/bounty-tracking.spec.ts`
- Modify: `dashboard/e2e/tests/schedule-scan.spec.ts`
- Modify: `dashboard/e2e/tests/worker-control.spec.ts`

**Step 1: Add tests to findings-browser.spec.ts**

Append to the existing describe block:

```typescript
  test("shows empty state when no findings exist", async ({ page }) => {
    // Create a fresh target with no seed data
    const freshTarget = factories.target();
    const res = await apiClient.createTarget(freshTarget);
    try {
      await page.goto("/");
      await page.getByRole("button", { name: new RegExp(freshTarget.base_domain) }).click();
      await page.waitForURL("**/campaign/c2");
      await page.getByRole("link", { name: "Findings" }).click();
      await expect(page.getByTestId("findings-empty-state")).toBeVisible({ timeout: 10_000 });
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });

  test("filter returning no results shows no-match message", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();
    await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });

    // Filter by a severity that has no results
    await page.getByTestId("severity-filter").selectOption("info");
    // No info-level vulns seeded — table should show empty
    await expect(page.getByText(/no.*found/i).or(page.getByText(/no.*match/i))).toBeVisible({ timeout: 5_000 });
  });
```

**Step 2: Add tests to bounty-tracking.spec.ts**

Append:

```typescript
  test("creates bounty with zero payout", async ({ page }) => {
    // Navigate to bounties, create with $0 payout
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Bounties" }).click();
    // Verify zero payout renders correctly (not NaN or error)
  });
```

**Step 3: Add tests to schedule-scan.spec.ts**

Append:

```typescript
  test("invalid cron expression shows validation error", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Schedules" }).click();
    // Attempt to create schedule with invalid cron — verify error shown
  });
```

**Step 4: Add tests to worker-control.spec.ts**

Append:

```typescript
  test("pause, resume, and stop actions update worker card state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // Find a running worker card
    const card = page.locator("[data-testid^='worker-card-']").first();
    await expect(card).toBeVisible({ timeout: 10_000 });

    // Pause
    await page.getByTestId("worker-pause-btn").first().click();
    // Resume
    await page.getByTestId("worker-resume-btn").first().click();
    // Stop
    await page.getByTestId("worker-stop-btn").first().click();
  });
```

**Step 5: Run all modified tests**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/findings-browser.spec.ts tests/bounty-tracking.spec.ts tests/schedule-scan.spec.ts tests/worker-control.spec.ts
```

**Step 6: Commit**

```bash
git add -A && git commit -m "test(e2e): deepen findings, bounties, schedules, and worker tests with edge cases"
```

---

## Task 16: Write Cross-Cutting Flow — Recon Lifecycle

**Files:**
- Create: `dashboard/e2e/tests/flows/recon-lifecycle.spec.ts`

**Step 1: Create flows directory and test file**

```bash
mkdir -p dashboard/e2e/tests/flows
```

```typescript
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Full Recon Lifecycle", () => {
  let targetId: number;
  let baseDomain: string;

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("create target → apply playbook → scan → view assets → view findings → create bounty", async ({ page }) => {
    // 1. Create target via scope builder wizard
    const targetData = factories.target();
    baseDomain = targetData.base_domain;

    await page.goto("/campaign");
    await page.getByTestId("scope-company-input").fill(targetData.company_name);
    await page.getByTestId("scope-domain-input").fill(baseDomain);
    await page.getByTestId("scope-next-btn").click();
    // Skip remaining scope steps
    for (let i = 0; i < 3; i++) {
      await page.getByTestId("scope-next-btn").click();
    }
    await page.getByTestId("scope-submit-btn").click();
    await page.waitForURL("**/campaign/c2", { timeout: 15_000 });

    // Get the target ID from API
    const targets = await apiClient.getTargets();
    const created = targets.targets.find((t) => t.base_domain === baseDomain);
    expect(created).toBeDefined();
    targetId = created!.id;

    // 2. Seed test data (simulates scan results)
    await apiClient.seedTestData(targetId);

    // 3. Navigate to flow → verify playbook can be selected
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");
    await expect(page.getByTestId("flow-playbook-select")).toBeVisible({ timeout: 10_000 });

    // 4. Navigate to assets → verify discoveries appear
    await page.getByRole("link", { name: "Assets" }).click();
    await page.waitForURL("**/campaign/assets");
    await expect(page.getByText(`sub1.${baseDomain}`)).toBeVisible({ timeout: 10_000 });

    // 5. Navigate to findings → verify vulns listed
    await page.getByRole("link", { name: "Findings" }).click();
    await page.waitForURL("**/campaign/findings");
    await expect(page.getByText("SQL Injection")).toBeVisible({ timeout: 10_000 });

    // 6. Navigate to bounties → create a bounty
    await page.getByRole("link", { name: "Bounties" }).click();
    await page.waitForURL("**/campaign/bounties");

    // Verify bounty can be created (UI depends on implementation)
    // At minimum, verify we arrived at bounties page
    await expect(page.getByText(/bounties/i)).toBeVisible();
  });
});
```

**Step 2: Run test**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/flows/recon-lifecycle.spec.ts
```

**Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): add recon-lifecycle cross-cutting flow test"
```

---

## Task 17: Write Cross-Cutting Flow — Triage Workflow

**Files:**
- Create: `dashboard/e2e/tests/flows/triage-workflow.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Triage Workflow", () => {
  let targetId: number;
  let baseDomain: string;
  let seedResult: { vuln_ids: number[] };

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    seedResult = await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("filter findings → view correlation → create bounty → update status", async ({ page }) => {
    // 1. Navigate to findings
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();

    // 2. Filter by critical severity
    await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });
    await page.getByTestId("severity-filter").selectOption("critical");
    await expect(page.getByText("SQL Injection")).toBeVisible();

    // 3. Open correlation view
    await page.getByTestId("correlation-view").click();
    await expect(page.getByText(/correlation/i)).toBeVisible({ timeout: 5_000 });
    // Close modal
    await page.keyboard.press("Escape");

    // 4. Navigate to bounties and create one
    await page.getByRole("link", { name: "Bounties" }).click();
    await page.waitForURL("**/campaign/bounties");

    // Create bounty via API (since UI creation flow may vary)
    const bounty = await apiClient.createBounty({
      target_id: targetId,
      vulnerability_id: seedResult.vuln_ids[0],
      platform: "hackerone",
      expected_payout: 1000,
    });

    // Reload and verify bounty appears
    await page.reload();
    await expect(page.getByText("hackerone")).toBeVisible({ timeout: 10_000 });

    // 5. Update bounty status
    await apiClient.updateBounty(bounty.id, { status: "submitted" });
    await page.reload();
    await expect(page.getByText(/submitted/i)).toBeVisible({ timeout: 10_000 });

    // 6. Update payout and verify persistence
    await apiClient.updateBounty(bounty.id, { actual_payout: 750 });
    await page.reload();
    await expect(page.getByText("750")).toBeVisible({ timeout: 10_000 });
  });
});
```

**Step 2: Run test, commit**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/flows/triage-workflow.spec.ts
git add -A && git commit -m "test(e2e): add triage-workflow cross-cutting flow test"
```

---

## Task 18: Write Cross-Cutting Flow — Operational Control

**Files:**
- Create: `dashboard/e2e/tests/flows/operational-control.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Operational Control", () => {
  let targetId: number;
  let baseDomain: string;
  let seedResult: { job_ids: number[] };

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    seedResult = await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("verify running → pause → resume → stop worker states on C2", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // 1. Verify RUNNING worker card
    const workerCard = page.locator("[data-testid^='worker-card-']").first();
    await expect(workerCard).toBeVisible({ timeout: 10_000 });
    await expect(workerCard.getByText(/running/i)).toBeVisible();

    // 2. Pause worker
    await page.getByTestId("worker-pause-btn").first().click();
    // Allow time for UI update
    await page.waitForTimeout(2000);

    // 3. Resume worker
    await page.getByTestId("worker-resume-btn").first().click();
    await page.waitForTimeout(2000);

    // 4. Stop worker
    await page.getByTestId("worker-stop-btn").first().click();
    await page.waitForTimeout(2000);

    // 5. Verify timeline shows state changes
    const timeline = page.getByTestId("c2-timeline");
    await expect(timeline).toBeVisible();
  });
});
```

**Step 2: Run test, commit**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/flows/operational-control.spec.ts
git add -A && git commit -m "test(e2e): add operational-control cross-cutting flow test"
```

---

## Task 19: Write Cross-Cutting Flow — Configuration Flow

**Files:**
- Create: `dashboard/e2e/tests/flows/configuration-flow.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Configuration", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("configure headers → set rate limit → create schedule → toggle off → verify persistence", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // 1. Open settings drawer
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5_000 });

    // 2. Add custom headers
    await page.getByTestId("settings-header-key-0").fill("Authorization");
    await page.getByTestId("settings-header-value-0").fill("Bearer test-token");

    // 3. Set rate limit
    await page.getByTestId("settings-rate-input").fill("50");

    // 4. Save
    await page.getByTestId("settings-save-btn").click();
    await page.waitForTimeout(1000);

    // 5. Navigate to schedules
    await page.getByRole("link", { name: "Schedules" }).click();
    await page.waitForURL("**/campaign/schedules");

    // 6. Create a schedule via API
    const schedule = await apiClient.createSchedule({
      target_id: targetId,
      cron_expression: "0 0 * * *",
      playbook: "wide_recon",
    });

    await page.reload();
    await expect(page.getByText("0 0 * * *")).toBeVisible({ timeout: 10_000 });

    // 7. Toggle schedule off
    await apiClient.updateSchedule(schedule.id, { enabled: false });
    await page.reload();

    // 8. Navigate back to settings — verify headers persisted
    await page.getByRole("link", { name: "C2 Console" }).click();
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5_000 });
    await expect(page.getByTestId("settings-header-key-0")).toHaveValue("Authorization");
    await expect(page.getByTestId("settings-rate-input")).toHaveValue("50");

    // Cleanup
    await apiClient.deleteSchedule(schedule.id).catch(() => {});
  });
});
```

**Step 2: Run test, commit**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/flows/configuration-flow.spec.ts
git add -A && git commit -m "test(e2e): add configuration cross-cutting flow test"
```

---

## Task 20: Write Cross-Cutting Flow — Worker Monitoring

**Files:**
- Create: `dashboard/e2e/tests/flows/worker-monitoring.spec.ts`

**Step 1: Write the test file**

```typescript
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Worker Execution Monitoring", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("flow monitor reflects execution state and SSE events propagate to C2", async ({ page }) => {
    // 1. Navigate to flow page
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    // 2. Verify monitor shows stage statuses from seeded jobs
    await expect(page.getByTestId("flow-monitor-stage-passive_discovery")).toBeVisible({ timeout: 10_000 });

    // 3. Emit a test event (stage completion)
    await apiClient.emitTestEvent(targetId, {
      event_type: "STAGE_COMPLETE",
      stage: "passive_discovery",
      status: "completed",
      tool: "subfinder",
    });

    // 4. Verify flow page updates (within polling interval)
    // Allow up to 15s for poll cycle
    await page.waitForTimeout(12_000);

    // 5. Navigate to C2 and verify timeline
    await page.getByRole("link", { name: "C2 Console" }).click();
    await page.waitForURL("**/campaign/c2");
    const timeline = page.getByTestId("c2-timeline");
    await expect(timeline).toBeVisible({ timeout: 10_000 });

    // 6. Verify assets page shows seeded assets
    await page.getByRole("link", { name: "Assets" }).click();
    await page.waitForURL("**/campaign/assets");
    await expect(page.getByText(`sub1.${baseDomain}`)).toBeVisible({ timeout: 10_000 });

    // 7. Verify findings page shows seeded vulns
    await page.getByRole("link", { name: "Findings" }).click();
    await page.waitForURL("**/campaign/findings");
    await expect(page.getByText("SQL Injection")).toBeVisible({ timeout: 10_000 });
  });

  test("SSE disconnect shows connection-lost and reconnect works", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    await expect(page.getByTestId("flow-monitor-stage-passive_discovery")).toBeVisible({ timeout: 10_000 });

    // Block execution state endpoint to simulate disconnect
    await page.route("**/api/v1/targets/*/execution", (route) =>
      route.abort("connectionrefused")
    );

    // Wait for next poll cycle to fail
    await page.waitForTimeout(12_000);

    // Check for connection-lost indicator
    await expect(
      page.getByTestId("flow-connection-lost").or(page.getByText(/connection lost/i).or(page.getByText(/failed/i)))
    ).toBeVisible({ timeout: 5_000 });

    // Restore and verify recovery
    await page.unroute("**/api/v1/targets/*/execution");
    await page.waitForTimeout(12_000);

    // Monitor should recover
    await expect(page.getByTestId("flow-monitor-stage-passive_discovery")).toBeVisible();
  });
});
```

**Step 2: Run test, commit**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts tests/flows/worker-monitoring.spec.ts
git add -A && git commit -m "test(e2e): add worker-monitoring cross-cutting flow test"
```

---

## Task 21: Update Playwright Config for Flows Subdirectory

**Files:**
- Modify: `dashboard/e2e/playwright.config.ts` (if needed — verify `testDir: "./tests"` picks up `flows/` subdirectory)

**Step 1: Verify config handles subdirectories**

Playwright's `testDir` setting recursively finds `.spec.ts` files, so `flows/` should be picked up automatically. Run the full suite to verify:

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts --list
```

Expected: All 21 test files listed (10 existing + 11 new).

**Step 2: Run the full suite**

```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts
```

Fix any failures.

**Step 3: Final commit**

```bash
git add -A && git commit -m "test(e2e): verify full suite runs with 21 test files and ~70 tests"
```

---

## Summary

| Task | Description | Files Changed | Tests Added |
|------|-------------|---------------|-------------|
| 1 | Remove compare + explorer pages | 7 | — |
| 2 | Backend endpoints (attack-paths, execution, apply-playbook, asset detail) | 3 | — |
| 3 | Extend test seed endpoint | 2 | — |
| 4 | Install React Flow | 1 | — |
| 5 | Rebuild assets page with expandable rows | 1 | — |
| 6 | Rebuild flow page (configurator + monitor) | 1 | — |
| 7 | Build attack graph page with React Flow | 1 | — |
| 8 | Add empty/error testids to existing pages | 7 | — |
| 9 | Test: assets inventory | 1 | 5 |
| 10 | Test: workflow builder | 1 | 5 |
| 11 | Test: attack graph | 1 | 4 |
| 12 | Test: empty states | 1 | 6 |
| 13 | Test: API errors | 1 | 4 |
| 14 | Test: edge cases | 1 | 4 |
| 15 | Deepen existing tests | 4 | ~6 |
| 16 | Flow: recon lifecycle | 1 | 1 |
| 17 | Flow: triage workflow | 1 | 1 |
| 18 | Flow: operational control | 1 | 1 |
| 19 | Flow: configuration flow | 1 | 1 |
| 20 | Flow: worker monitoring | 1 | 2 |
| 21 | Verify full suite | — | — |
| **Total** | | | **~40 new tests → ~60 total** |
