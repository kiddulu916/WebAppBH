# Target Management Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add target lifecycle management — enhanced clean_slate with Redis purge, a DELETE endpoint that nukes a target from everything, extended GET /api/v1/targets with stats, and a new /campaign/targets dashboard page.

**Architecture:** Three backend changes in `orchestrator/main.py` (enhance clean_slate, add DELETE endpoint, extend GET targets with stats). One new dashboard page at `/campaign/targets` using the existing table pattern from `assets/page.tsx`. One new API method in `api.ts`. One sidebar nav entry.

**Tech Stack:** FastAPI, SQLAlchemy (async), Redis Streams, Next.js 16, React 19, Zustand, Tailwind CSS v4, Lucide icons.

**Design doc:** `docs/plans/design/2026-03-24-target-management-design.md`

---

## Task 1: Enhance clean_slate to purge Redis stream

**Files:**
- Modify: `orchestrator/main.py:548-607` (clean_slate endpoint)

**Step 1: Add Redis stream deletion to clean_slate**

After the existing `push_task(f"events:{target_id}", ...)` call at line 602, add a Redis `DELETE` for the events stream. The CLEAN_SLATE SSE event should be pushed *before* the stream is deleted so any connected dashboard receives it. Add a short delay to allow SSE delivery.

```python
@app.post("/api/v1/targets/{target_id}/clean-slate")
async def clean_slate(target_id: int):
    """Delete all discovered data for a target. Preserves target, config, bounties."""
    from sqlalchemy import delete
    active_statuses = ["RUNNING", "QUEUED", "PAUSED"]

    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        active = (await session.execute(
            select(func.count(JobState.id)).where(
                JobState.target_id == target_id,
                JobState.status.in_(active_statuses),
            )
        )).scalar()
        if active > 0:
            raise HTTPException(status_code=409, detail="Active jobs exist. Kill them first.")

        # Delete in dependency order — child tables first.
        asset_ids = select(Asset.id).where(Asset.target_id == target_id)

        bounty_vuln_ids = select(BountySubmission.vulnerability_id).where(
            BountySubmission.target_id == target_id
        )

        # Delete vulns NOT referenced by bounties
        await session.execute(
            delete(Vulnerability).where(
                Vulnerability.target_id == target_id,
                Vulnerability.id.notin_(bounty_vuln_ids),
            )
        )

        await session.execute(delete(Parameter).where(Parameter.asset_id.in_(asset_ids)))
        await session.execute(delete(ApiSchema).where(ApiSchema.target_id == target_id))
        await session.execute(delete(MobileApp).where(MobileApp.target_id == target_id))
        await session.execute(delete(Location).where(Location.asset_id.in_(asset_ids)))
        await session.execute(delete(Observation).where(Observation.asset_id.in_(asset_ids)))
        await session.execute(delete(Identity).where(Identity.target_id == target_id))
        await session.execute(delete(CloudAsset).where(CloudAsset.target_id == target_id))
        await session.execute(delete(AssetSnapshot).where(AssetSnapshot.target_id == target_id))
        await session.execute(delete(ScopeViolation).where(ScopeViolation.target_id == target_id))
        await session.execute(delete(Alert).where(Alert.target_id == target_id))
        await session.execute(delete(JobState).where(JobState.target_id == target_id))
        await session.execute(delete(Asset).where(Asset.target_id == target_id))

        await session.commit()

    # Emit event before purging the stream
    await push_task(f"events:{target_id}", {
        "event": "CLEAN_SLATE",
        "target_id": target_id,
    })

    # Brief delay to let SSE consumers receive the event
    await asyncio.sleep(0.5)

    # Purge the Redis event stream
    r = get_redis()
    await r.delete(f"events:{target_id}")

    return {"success": True, "target_id": target_id}
```

**Step 2: Verify**

Run: `docker compose up orchestrator` and test via curl:
```bash
curl -X POST http://localhost:8001/api/v1/targets/1/clean-slate -H "X-API-KEY: $KEY"
```
Expected: `{"success": true, "target_id": 1}` and the `events:1` Redis key should be gone.

**Step 3: Commit**

```bash
git add orchestrator/main.py
git commit -m "feat: purge Redis events stream on clean_slate"
```

---

## Task 2: Add DELETE /api/v1/targets/{target_id} endpoint

**Files:**
- Modify: `orchestrator/main.py` — add new endpoint after the clean_slate block (~line 607)

**Step 1: Add the delete endpoint**

Insert after the clean_slate endpoint. This endpoint:
1. Verifies target exists (404)
2. Auto-kills running containers via `worker_manager.kill_worker()`
3. Deletes the Target row (cascades to all child tables)
4. Deletes `events:{target_id}` Redis stream
5. Deletes config/reports directories

```python
# ---------------------------------------------------------------------------
# DELETE /api/v1/targets/{target_id} — fully delete a target
# ---------------------------------------------------------------------------
@app.delete("/api/v1/targets/{target_id}")
async def delete_target(target_id: int):
    """Permanently delete a target and all associated data, containers, config, and reports."""
    from sqlalchemy import delete as sa_delete
    import shutil

    # 1. Verify target exists
    async with get_session() as session:
        target = (await session.execute(
            select(Target).where(Target.id == target_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

    # 2. Auto-kill any running containers for this target
    containers = await worker_manager.list_webbh_containers()
    killed = []
    for c in containers:
        if c.name.endswith(f"-t{target_id}") and c.status in ("running", "paused"):
            await worker_manager.kill_worker(c.name)
            killed.append(c.name)

    if killed:
        logger.info("Auto-killed containers for target deletion",
                     extra={"target_id": target_id, "killed": killed})

    # 3. Delete target row (cascades to all child tables)
    async with get_session() as session:
        await session.execute(
            sa_delete(Target).where(Target.id == target_id)
        )
        await session.commit()

    # 4. Purge Redis event stream
    r = get_redis()
    await r.delete(f"events:{target_id}")

    # 5. Remove config directory
    config_dir = SHARED_CONFIG / str(target_id)
    if config_dir.exists():
        shutil.rmtree(config_dir)
        logger.info("Removed config dir", extra={"path": str(config_dir)})

    # 6. Remove reports directory
    reports_dir = SHARED_REPORTS / str(target_id)
    if reports_dir.exists():
        shutil.rmtree(reports_dir)
        logger.info("Removed reports dir", extra={"path": str(reports_dir)})

    logger.info("Target deleted", extra={"target_id": target_id, "killed_containers": killed})

    return {"success": True, "target_id": target_id}
```

**Step 2: Update the docstring at the top of main.py**

Add the new endpoint to the module-level docstring (around line 5-30):
```
DELETE /api/v1/targets/{target_id} – permanently delete a target
```

**Step 3: Verify**

```bash
curl -X DELETE http://localhost:8001/api/v1/targets/1 -H "X-API-KEY: $KEY"
```
Expected: `{"success": true, "target_id": 1}`. Target row, all child rows, Redis stream, config dir, and reports dir should all be gone.

**Step 4: Commit**

```bash
git add orchestrator/main.py
git commit -m "feat: add DELETE /api/v1/targets/{target_id} endpoint"
```

---

## Task 3: Extend GET /api/v1/targets with aggregated stats

**Files:**
- Modify: `orchestrator/main.py:717-737` (list_targets endpoint)

**Step 1: Rewrite list_targets to include stats**

Replace the existing `list_targets` function with a version that joins asset counts, vuln counts, and job state aggregation.

```python
@app.get("/api/v1/targets")
async def list_targets():
    async with get_session() as session:
        stmt = select(Target).order_by(Target.created_at.desc())
        result = await session.execute(stmt)
        targets = result.scalars().all()

        target_ids = [t.id for t in targets]

        # Asset counts per target
        asset_counts: dict[int, int] = {}
        if target_ids:
            ac_stmt = (
                select(Asset.target_id, func.count(Asset.id))
                .where(Asset.target_id.in_(target_ids))
                .group_by(Asset.target_id)
            )
            for tid, cnt in (await session.execute(ac_stmt)).all():
                asset_counts[tid] = cnt

        # Vuln counts per target
        vuln_counts: dict[int, int] = {}
        if target_ids:
            vc_stmt = (
                select(Vulnerability.target_id, func.count(Vulnerability.id))
                .where(Vulnerability.target_id.in_(target_ids))
                .group_by(Vulnerability.target_id)
            )
            for tid, cnt in (await session.execute(vc_stmt)).all():
                vuln_counts[tid] = cnt

        # Job status + last activity per target
        # Priority: RUNNING > QUEUED > PAUSED > COMPLETED > FAILED > idle
        job_info: dict[int, dict] = {}
        if target_ids:
            js_stmt = (
                select(
                    JobState.target_id,
                    JobState.status,
                    func.max(JobState.updated_at).label("last_activity"),
                )
                .where(JobState.target_id.in_(target_ids))
                .group_by(JobState.target_id, JobState.status)
            )
            rows = (await session.execute(js_stmt)).all()

            status_priority = {
                "RUNNING": 6, "QUEUED": 5, "PAUSED": 4,
                "COMPLETED": 3, "FAILED": 2, "KILLED": 1, "STOPPED": 1,
            }

            for tid, status, last_act in rows:
                existing = job_info.get(tid)
                prio = status_priority.get(status, 0)
                if existing is None or prio > existing["priority"]:
                    job_info[tid] = {
                        "status": status.lower(),
                        "last_activity": last_act,
                        "priority": prio,
                    }
                elif existing and last_act and (
                    existing["last_activity"] is None or last_act > existing["last_activity"]
                ):
                    existing["last_activity"] = last_act

    return {
        "targets": [
            {
                "id": t.id,
                "company_name": t.company_name,
                "base_domain": t.base_domain,
                "target_profile": t.target_profile,
                "last_playbook": t.last_playbook,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                "asset_count": asset_counts.get(t.id, 0),
                "vuln_count": vuln_counts.get(t.id, 0),
                "status": job_info.get(t.id, {}).get("status", "idle"),
                "last_activity": (
                    job_info[t.id]["last_activity"].isoformat()
                    if t.id in job_info and job_info[t.id]["last_activity"]
                    else t.updated_at.isoformat() if t.updated_at else None
                ),
            }
            for t in targets
        ],
    }
```

**Step 2: Verify**

```bash
curl http://localhost:8001/api/v1/targets -H "X-API-KEY: $KEY" | python3 -m json.tool
```
Expected: Each target now includes `asset_count`, `vuln_count`, `status`, `last_activity` fields.

**Step 3: Commit**

```bash
git add orchestrator/main.py
git commit -m "feat: extend GET /api/v1/targets with asset/vuln counts and status"
```

---

## Task 4: Add deleteTarget method to dashboard api.ts

**Files:**
- Modify: `dashboard/src/lib/api.ts`
- Modify: `dashboard/src/types/schema.ts`

**Step 1: Add TargetWithStats interface to schema.ts**

Add after the existing `Target` interface (line 53):

```typescript
export interface TargetWithStats extends Target {
  asset_count: number;
  vuln_count: number;
  status: string;
  last_activity: string | null;
}
```

**Step 2: Update TargetsResponse and add deleteTarget in api.ts**

Update the `TargetsResponse` interface (line 146-148) to use `TargetWithStats`:

```typescript
interface TargetsResponse {
  targets: import("@/types/schema").TargetWithStats[];
}
```

Add the `deleteTarget` method inside the `api` object, after `cleanSlate` (line 543):

```typescript
  deleteTarget(targetId: number) {
    return request<{ success: boolean; target_id: number }>(
      `/api/v1/targets/${targetId}`,
      { method: "DELETE" },
    );
  },
```

**Step 3: Verify**

```bash
cd dashboard && npx tsc --noEmit
```
Expected: No type errors.

**Step 4: Commit**

```bash
git add dashboard/src/lib/api.ts dashboard/src/types/schema.ts
git commit -m "feat: add deleteTarget API method and TargetWithStats type"
```

---

## Task 5: Create /campaign/targets page

**Files:**
- Create: `dashboard/src/app/campaign/targets/page.tsx`

**Step 1: Create the targets management page**

This follows the same pattern as `campaign/assets/page.tsx` — `"use client"`, Zustand store, `api` calls, manual sort/filter/pagination, Tailwind table.

Key differences from other campaign pages:
- This page does NOT require `activeTarget` — it shows ALL targets.
- Two action buttons per row: "Erase Data" (calls `api.cleanSlate`) and "Delete Target" (calls `api.deleteTarget`).
- Erase confirmation: simple danger dialog.
- Delete confirmation: requires typing the base_domain to confirm.

```tsx
"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import {
  Loader2,
  Search,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Trash2,
  Eraser,
  MoreVertical,
} from "lucide-react";
import { api } from "@/lib/api";
import type { TargetWithStats } from "@/types/schema";

type SortKey = "company_name" | "base_domain" | "status" | "asset_count" | "vuln_count" | "last_activity";
type SortDir = "asc" | "desc";

const PAGE_SIZE = 25;

const STATUS_BADGE: Record<string, string> = {
  running: "bg-neon-green-glow text-neon-green border-neon-green/20",
  queued: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  paused: "bg-neon-orange-glow text-neon-orange border-neon-orange/20",
  completed: "bg-bg-surface text-text-muted border-border",
  failed: "bg-danger/15 text-danger border-danger/25",
  idle: "bg-bg-surface text-text-muted border-border",
};

export default function TargetsPage() {
  const [data, setData] = useState<TargetWithStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("last_activity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(0);

  // Erase dialog state
  const [eraseTarget, setEraseTarget] = useState<TargetWithStats | null>(null);
  const [erasing, setErasing] = useState(false);

  // Delete dialog state
  const [deleteTarget, setDeleteTarget] = useState<TargetWithStats | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleting, setDeleting] = useState(false);

  // Dropdown menu state
  const [menuOpen, setMenuOpen] = useState<number | null>(null);

  const fetchTargets = useCallback(async () => {
    try {
      const res = await api.getTargets();
      setData(res.targets);
    } catch {
      // toast shown by api.request()
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

  const toggleSort = useCallback(
    (key: SortKey) => {
      if (sortKey === key) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortKey(key);
        setSortDir("asc");
      }
      setPage(0);
    },
    [sortKey],
  );

  const filtered = useMemo(() => {
    let rows = data;
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter(
        (r) =>
          r.company_name.toLowerCase().includes(q) ||
          r.base_domain.toLowerCase().includes(q),
      );
    }
    rows = [...rows].sort((a, b) => {
      const av = a[sortKey] ?? "";
      const bv = b[sortKey] ?? "";
      if (typeof av === "number" && typeof bv === "number") {
        return sortDir === "asc" ? av - bv : bv - av;
      }
      return sortDir === "asc"
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });
    return rows;
  }, [data, search, sortKey, sortDir]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const handleErase = async () => {
    if (!eraseTarget) return;
    setErasing(true);
    try {
      await api.cleanSlate(eraseTarget.id);
      await fetchTargets();
    } catch {
      // toast shown by api.request()
    } finally {
      setErasing(false);
      setEraseTarget(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget || deleteConfirm !== deleteTarget.base_domain) return;
    setDeleting(true);
    try {
      await api.deleteTarget(deleteTarget.id);
      await fetchTargets();
    } catch {
      // toast shown by api.request()
    } finally {
      setDeleting(false);
      setDeleteTarget(null);
      setDeleteConfirm("");
    }
  };

  const SortHeader = ({ label, field }: { label: string; field: SortKey }) => (
    <button
      onClick={() => toggleSort(field)}
      className="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-text-muted hover:text-text-primary"
    >
      {label}
      <ArrowUpDown className="h-3 w-3" />
    </button>
  );

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-accent" />
      </div>
    );
  }

  return (
    <div className="space-y-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold text-text-primary">
            Target Management
          </h1>
          <span className="rounded-full bg-bg-surface px-2 py-0.5 text-xs font-mono text-text-muted border border-border">
            {data.length}
          </span>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Search targets..."
            className="h-8 w-56 rounded-md border border-border bg-bg-secondary pl-9 pr-3 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 py-3 text-left">
                <SortHeader label="Company" field="company_name" />
              </th>
              <th className="px-4 py-3 text-left">
                <SortHeader label="Domain" field="base_domain" />
              </th>
              <th className="px-4 py-3 text-left">
                <SortHeader label="Status" field="status" />
              </th>
              <th className="px-4 py-3 text-right">
                <SortHeader label="Assets" field="asset_count" />
              </th>
              <th className="px-4 py-3 text-right">
                <SortHeader label="Vulns" field="vuln_count" />
              </th>
              <th className="px-4 py-3 text-left">
                <SortHeader label="Last Activity" field="last_activity" />
              </th>
              <th className="px-4 py-3 text-right">
                <span className="text-xs font-medium uppercase tracking-wider text-text-muted">
                  Actions
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {paged.map((t) => (
              <tr
                key={t.id}
                className="border-b border-border/50 last:border-0 hover:bg-bg-tertiary/50"
              >
                <td className="px-4 py-3 font-medium text-text-primary">
                  {t.company_name}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-text-secondary">
                  {t.base_domain}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[t.status] ?? STATUS_BADGE.idle}`}
                  >
                    {t.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-right font-mono text-xs text-text-secondary">
                  {t.asset_count.toLocaleString()}
                </td>
                <td className="px-4 py-3 text-right font-mono text-xs text-text-secondary">
                  {t.vuln_count.toLocaleString()}
                </td>
                <td className="px-4 py-3 text-xs text-text-muted">
                  {t.last_activity
                    ? new Date(t.last_activity).toLocaleString()
                    : "—"}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="relative inline-block">
                    <button
                      onClick={() =>
                        setMenuOpen(menuOpen === t.id ? null : t.id)
                      }
                      className="rounded p-1 text-text-muted hover:bg-bg-surface hover:text-text-primary"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                    {menuOpen === t.id && (
                      <div className="absolute right-0 top-full z-20 mt-1 w-44 rounded-md border border-border bg-bg-secondary shadow-lg">
                        <button
                          onClick={() => {
                            setEraseTarget(t);
                            setMenuOpen(null);
                          }}
                          className="flex w-full items-center gap-2 px-3 py-2 text-xs text-text-secondary hover:bg-bg-tertiary hover:text-neon-orange"
                        >
                          <Eraser className="h-3.5 w-3.5" />
                          Erase Data
                        </button>
                        <button
                          onClick={() => {
                            setDeleteTarget(t);
                            setMenuOpen(null);
                          }}
                          className="flex w-full items-center gap-2 px-3 py-2 text-xs text-text-secondary hover:bg-bg-tertiary hover:text-danger"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          Delete Target
                        </button>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {paged.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-8 text-center text-sm text-text-muted"
                >
                  {search ? "No targets match your search." : "No targets yet."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-text-muted">
          <span>
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of{" "}
            {filtered.length}
          </span>
          <div className="flex gap-1">
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
              className="rounded p-1 hover:bg-bg-surface disabled:opacity-30"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
              className="rounded p-1 hover:bg-bg-surface disabled:opacity-30"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Erase Confirmation Dialog */}
      {eraseTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
          onClick={() => !erasing && setEraseTarget(null)}
        >
          <div
            className="w-96 rounded-lg border border-neon-orange/30 bg-bg-secondary p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-sm font-semibold text-text-primary">
              Erase Target Data
            </h3>
            <p className="mt-2 text-xs text-text-muted">
              This will permanently erase all discovered assets, vulnerabilities,
              jobs, and alerts for{" "}
              <span className="font-semibold text-text-primary">
                {eraseTarget.company_name}
              </span>{" "}
              ({eraseTarget.base_domain}). The target and bounty submissions are
              preserved. This cannot be undone.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                disabled={erasing}
                onClick={() => setEraseTarget(null)}
                className="rounded-md border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-bg-tertiary"
              >
                Cancel
              </button>
              <button
                disabled={erasing}
                onClick={handleErase}
                className="rounded-md bg-neon-orange/20 px-3 py-1.5 text-xs font-medium text-neon-orange border border-neon-orange/30 hover:bg-neon-orange/30 disabled:opacity-50"
              >
                {erasing ? "Erasing..." : "Erase Data"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      {deleteTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
          onClick={() => !deleting && setDeleteTarget(null)}
        >
          <div
            className="w-96 rounded-lg border border-danger/30 bg-bg-secondary p-5 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-sm font-semibold text-danger">
              Delete Target Permanently
            </h3>
            <p className="mt-2 text-xs text-text-muted">
              This will permanently delete{" "}
              <span className="font-semibold text-text-primary">
                {deleteTarget.company_name}
              </span>{" "}
              and ALL associated data including bounty submissions, config, and
              reports. Any running workers will be killed.
            </p>
            <p className="mt-3 text-xs text-text-muted">
              Type{" "}
              <span className="font-mono font-semibold text-danger">
                {deleteTarget.base_domain}
              </span>{" "}
              to confirm:
            </p>
            <input
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
              placeholder={deleteTarget.base_domain}
              className="mt-2 w-full rounded-md border border-border bg-bg-primary px-3 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-muted/40 focus:border-danger focus:outline-none"
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                disabled={deleting}
                onClick={() => {
                  setDeleteTarget(null);
                  setDeleteConfirm("");
                }}
                className="rounded-md border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-bg-tertiary"
              >
                Cancel
              </button>
              <button
                disabled={
                  deleting || deleteConfirm !== deleteTarget.base_domain
                }
                onClick={handleDelete}
                className="rounded-md bg-danger/20 px-3 py-1.5 text-xs font-medium text-danger border border-danger/30 hover:bg-danger/30 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {deleting ? "Deleting..." : "Delete Target"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
```

**Step 2: Verify**

```bash
cd dashboard && npx tsc --noEmit && npm run build
```
Expected: No type errors or build errors.

**Step 3: Commit**

```bash
git add dashboard/src/app/campaign/targets/page.tsx
git commit -m "feat: add /campaign/targets management page"
```

---

## Task 6: Add Targets link to sidebar navigation

**Files:**
- Modify: `dashboard/src/components/layout/Sidebar.tsx:17-26`

**Step 1: Add the nav item**

Import `Crosshair` from lucide-react (line 5 imports) and add the Targets entry to `NAV_ITEMS` array. Insert it after "New Campaign" (line 19) so it groups logically with campaign management.

Add to the import:
```tsx
import {
  Target,
  LayoutDashboard,
  Network,
  Shield,
  Cloud,
  Activity,
  Bug,
  GitGraph,
  Settings,
  Crosshair,
} from "lucide-react";
```

Update `NAV_ITEMS` — add after the "New Campaign" entry:
```tsx
const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/campaign", label: "New Campaign", icon: Target },
  { href: "/campaign/targets", label: "Targets", icon: Crosshair },
  { href: "/campaign/c2", label: "C2 Console", icon: Network },
  { href: "/campaign/graph", label: "Attack Graph", icon: GitGraph },
  { href: "/campaign/assets", label: "Assets", icon: Activity },
  { href: "/campaign/cloud", label: "Cloud", icon: Cloud },
  { href: "/campaign/vulns", label: "Vulnerabilities", icon: Bug },
  { href: "/campaign/findings", label: "All Findings", icon: Shield },
] as const;
```

**Step 2: Verify**

```bash
cd dashboard && npx tsc --noEmit
```
Expected: No errors. The sidebar should now show "Targets" between "New Campaign" and "C2 Console".

**Step 3: Commit**

```bash
git add dashboard/src/components/layout/Sidebar.tsx
git commit -m "feat: add Targets link to sidebar navigation"
```

---

## Task 7: Final integration test

**Step 1: Start the full stack**

```bash
docker compose up --build
```

**Step 2: Manual verification checklist**

1. Open dashboard at `http://localhost:3000/campaign/targets` — page loads, shows all targets.
2. Create a target if none exist, wait for some data to be collected.
3. Click the actions menu (three dots) on a target — dropdown shows "Erase Data" and "Delete Target".
4. Click "Erase Data" — confirmation dialog appears. Confirm — target stays but counts reset to 0.
5. Click "Delete Target" — severe dialog appears. Type wrong domain — button stays disabled. Type correct domain — button enables. Confirm — target disappears from the list.
6. Verify sidebar navigation — "Targets" link is present and active when on the targets page.

**Step 3: Final commit**

```bash
git add -A
git commit -m "feat: target management — erase data and delete target"
```
