# Target Management — Design Document

**Date:** 2026-03-24
**Goal:** Add target lifecycle management: erase collected data (enhanced clean_slate) and fully delete a target from the system.

---

## 1. API Changes

### 1.1 Enhanced clean_slate

**Endpoint:** `POST /api/v1/targets/{target_id}/clean-slate` (existing)

Current behavior preserved, plus:
- Delete the `events:{target_id}` Redis stream via `r.delete(f"events:{target_id}")`.

Preserves: target record, config files (`shared/config/{target_id}/`), bounty submissions and their linked vulnerabilities.

### 1.2 New delete endpoint

**Endpoint:** `DELETE /api/v1/targets/{target_id}`

Steps in order:
1. Verify target exists (404 if not).
2. Auto-kill any running containers matching `webbh-*-t{target_id}` using `worker_manager.kill_worker()`.
3. Delete the Target row from PostgreSQL. All child tables cascade (`cascade="all, delete-orphan"` on all relationships).
4. Delete `events:{target_id}` Redis stream.
5. Delete config directory `shared/config/{target_id}/` if it exists.
6. Delete reports directory `shared/reports/{target_id}/` if it exists.

Returns `{"success": true, "target_id": <id>}`.

### 1.3 Extended GET /api/v1/targets

Add aggregated stats per target in the response:
- `asset_count` — count of assets for the target.
- `vuln_count` — count of vulnerabilities for the target.
- `status` — aggregated from job_state: highest-priority active status across all workers (running > queued > paused > completed > failed > idle).
- `last_activity` — most recent `updated_at` across job_state rows for the target, or target's own `updated_at` if no jobs.

---

## 2. Dashboard — Target Management Page

### 2.1 Route

`/campaign/targets`

### 2.2 Layout

Page header: "Target Management" with target count badge.

TanStack Table with columns:

| Company | Domain | Status | Assets | Vulns | Last Activity | Actions |
|---------|--------|--------|--------|-------|---------------|---------|

- **Status** — badge derived from aggregated job_state (idle/running/queued/paused/completed/failed).
- **Actions** — dropdown menu with "Erase Data" and "Delete Target".

### 2.3 Confirmation dialogs

**Erase Data** — simple danger dialog:
> This will permanently erase all discovered data for {company_name} ({base_domain}). The target and bounty submissions are preserved. This cannot be undone.

Confirm / Cancel buttons.

**Delete Target** — severe dialog with domain confirmation:
> This will permanently delete {company_name} ({base_domain}) and ALL associated data including bounty submissions, config, and reports. Type the domain to confirm:

Text input that must match `base_domain` before the delete button enables.

---

## 3. File Changes

### Backend
1. `orchestrator/main.py` — Enhance `clean_slate` to purge `events:{target_id}` Redis stream. Add `DELETE /api/v1/targets/{target_id}` endpoint. Extend `GET /api/v1/targets` response to include aggregated stats.

### Dashboard
2. `dashboard/src/app/campaign/targets/page.tsx` — New target management page.
3. `dashboard/src/lib/api.ts` — Add `deleteTarget(targetId)` method.
4. Sidebar/nav — Add "Targets" link under campaign section.

### Not changing
- No new DB models or schema changes. Existing cascade handles cleanup.
- No new shared lib modules. Redis cleanup is a single `r.delete()` call.
- Container cleanup reuses `worker_manager.kill_worker()`.

---

## 4. Redis cleanup scope

Only `events:{target_id}` is deleted. Shared work queues (`recon_queue`, `fuzzing_queue`, etc.) are not scanned — workers already look up the target from the DB before processing; if the target is gone, the worker skips the message.
