# Kill Switch, Rerun & Clean Slate — Design

**Date:** 2026-03-22
**Scope:** Top-level kill switch, target rerun with playbook selection, clean slate reset, single-target enforcement

---

## Overview

Three new operational controls for the C2 console and framework:

1. **Kill Switch** — Hard-kill all active workers immediately (SIGKILL + container remove)
2. **Rerun** — Re-queue the active target with the last-ran or a different playbook, preserving existing data
3. **Clean Slate** — Wipe all discovered data for a target while preserving configuration and bounty submissions

Additionally, **single-target enforcement** ensures only one target has active workers at any time.

---

## Constraints

- Only one target may have active workers (RUNNING/QUEUED/PAUSED) at a time
- Kill is always hard-kill (SIGKILL), no graceful shutdown — this is a panic button
- Rerun preserves existing scan data; workers dedupe via cooldown checks
- Clean slate is intentionally buried in settings to prevent accidental data loss

---

## New API Endpoints

### POST /api/v1/kill

Hard-kill all workers for the active target.

**Request:** No body required.

**Logic:**
1. Query all `JobState` rows where `status IN ('RUNNING', 'QUEUED', 'PAUSED')`
2. For each RUNNING/PAUSED job — call `kill_worker(container_name)` (SIGKILL + container remove)
3. Bulk update all matched jobs to `status = 'KILLED'`
4. Push `KILL_ALL` event to `events:{target_id}` stream
5. Return response

**Response:**
```json
{ "success": true, "killed_count": 3, "containers": ["webbh-recon-t1", "webbh-fuzzing-t1", "webbh-cloud_testing-t1"] }
```

**Idempotent:** If no active jobs exist, returns `{ success: true, killed_count: 0, containers: [] }`.

---

### POST /api/v1/rerun

Rerun a target with a specified playbook.

**Request:**
```json
{ "target_id": 1, "playbook_name": "wide_recon" }
```

**Logic:**
1. Validate target exists and has no active jobs. If active, return 409.
2. Look up playbook in `BUILTIN_PLAYBOOKS` then `CustomPlaybook` table. Return 404 if not found.
3. Write playbook config to `shared/config/{target_id}/playbook.json`.
4. Update `Target.last_playbook` column with the selected playbook name.
5. Push task to `recon_queue` with `{ target_id, action: "rerun" }`.
6. Push `RERUN_STARTED` SSE event to `events:{target_id}`.
7. Return response.

**Response:**
```json
{ "success": true, "target_id": 1, "playbook_name": "wide_recon" }
```

---

### POST /api/v1/targets/{id}/clean-slate

Wipe all discovered data for a target. Preserves target record, config files, and bounty submissions.

**Request:** No body required.

**Logic:**
1. Validate target exists and has no active jobs. If active, return 409.
2. Delete in dependency order (single transaction, full rollback on failure):
   - Vulnerability
   - Parameter
   - ApiSchema
   - Location
   - Observation
   - Identity
   - CloudAsset
   - AssetSnapshot
   - ScopeViolation
   - Alert
   - JobState
   - Asset
3. Push `CLEAN_SLATE` SSE event to `events:{target_id}`.
4. Return response.

**Response:**
```json
{ "success": true, "target_id": 1 }
```

**Preserved:** Target row, BountySubmission records, config files in `shared/config/{target_id}/`.

---

## Single-Target Enforcement

**Enforcement point:** `POST /api/v1/targets` — before creating a new target, query `JobState` for any rows with `status IN ('RUNNING', 'QUEUED', 'PAUSED')`. If found, return 409:
```json
{ "error": "Target {name} is currently active. Stop it before starting a new target." }
```

**Event engine:** Existing `_check_*_trigger()` functions already skip targets with active jobs — no change needed. Add `KILLED` to the list of terminal statuses so triggers don't re-fire for killed targets.

**Rerun exception:** Rerun operates on the same target, so single-target enforcement doesn't apply. The rerun endpoint checks for active jobs on that specific target to prevent double-runs.

**Orphaned jobs:** If the system crashes mid-kill and leaves QUEUED jobs behind, the heartbeat's existing zombie cleanup (600s grace) marks them FAILED, clearing the lock.

---

## Database Changes

### New job status: KILLED

Distinct from FAILED — the operator chose to abort, it wasn't an error. Add to the exclusion list in event engine trigger checks alongside RUNNING, QUEUED, PAUSED.

### New column: Target.last_playbook

```python
last_playbook: Mapped[Optional[str]] = mapped_column(String, nullable=True)
```

Updated on every rerun and on initial target creation. The dashboard reads this to pre-select "Same Playbook" in the rerun popover.

---

## SSE Events

| Event | Payload | Purpose |
|-------|---------|---------|
| `KILL_ALL` | `{ killed_count, containers: [...], timestamp }` | Notify dashboard of kill completion |
| `RERUN_STARTED` | `{ playbook_name, target_id, timestamp }` | Notify dashboard rerun is queued |
| `CLEAN_SLATE` | `{ target_id, timestamp }` | Notify dashboard data was wiped |

---

## Dashboard Changes

### Kill Button — Top Nav (All Pages)

- **Position:** Right side of top nav bar, visible on every page
- **Style:** Red background, Lucide `Power` or `OctagonX` icon, text "KILL" (icon-only on small screens)
- **Click:** Confirmation AlertDialog — "Kill all active operations? This will immediately terminate all running workers."
- **Confirm:** `POST /api/v1/kill` → loading state → success toast "All operations killed"
- **Always enabled:** API is idempotent, killing nothing returns `killed_count: 0`

### Rerun Popover — C2 Page

- **Position:** C2 console toolbar/header area
- **Style:** Primary button with Lucide `RotateCcw` icon, text "Rerun"
- **Click:** Popover with two options:
  - **"Same Playbook"** — Subtitle shows last playbook name. Click fires `POST /api/v1/rerun` immediately with `last_playbook`.
  - **"Change Playbook"** — Swaps popover content to a list of available playbooks (built-in + custom from `GET /api/v1/playbooks`). No "create new" option, no tool selection. Click a playbook fires the rerun API.
- **Disabled state:** Disabled when jobs are active (RUNNING/QUEUED/PAUSED). Tooltip: "Kill current run first."
- **On success:** Popover closes, SSE delivers `RERUN_STARTED`, phase pipeline resets.

### Clean Slate — C2 Settings Drawer

- **Position:** Bottom of SettingsDrawer, under "Danger Zone" section with border separator
- **Style:** Red outlined button (not filled), text "Reset Target Data"
- **Click:** AlertDialog — "This will permanently delete all discovered assets, vulnerabilities, jobs, and alerts for this target. Configuration and bounty submissions are preserved. This cannot be undone."
- **Confirm:** `POST /api/v1/targets/{id}/clean-slate` → drawer closes → C2 resets → toast "Target data cleared"
- **Disabled state:** Disabled when jobs are active. Tooltip: "Kill current run first."

### C2 Console SSE Reactions

| Event | Reaction |
|-------|----------|
| `KILL_ALL` | Worker grid: cards flash red then show "killed" state. Phase pipeline: current stage marks aborted. Asset tree: unchanged. |
| `RERUN_STARTED` | Worker grid: clears, awaits new `WORKER_SPAWNED`. Phase pipeline: all stages reset to pending. |
| `CLEAN_SLATE` | Asset tree: empties. Worker grid: clears. Phase pipeline: resets. All counters zero. |

### Campaign Timeline

All three events logged to CampaignTimeline with distinct icons:
- Kill → red stop/skull icon
- Rerun → rotate icon
- Clean slate → eraser icon

---

## Files Modified

### Backend (Orchestrator + Shared Lib)
- `orchestrator/main.py` — Three new endpoints, single-target enforcement on target creation
- `orchestrator/worker_manager.py` — No changes (kill_worker already exists)
- `orchestrator/event_engine.py` — Add KILLED to terminal status exclusion list
- `shared/lib_webbh/database.py` — Add `last_playbook` column to Target model

### Dashboard
- `dashboard/src/components/nav/` — Kill button in top nav
- `dashboard/src/app/campaign/c2/page.tsx` — Rerun popover, SSE event handlers for new events
- `dashboard/src/app/campaign/c2/components/` — Settings drawer danger zone with clean slate
- `dashboard/src/lib/api.ts` — Three new API client methods (kill, rerun, cleanSlate)
