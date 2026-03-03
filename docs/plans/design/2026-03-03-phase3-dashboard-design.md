# Phase 3: C2 Dashboard Design

**Date:** 2026-03-03
**Phase:** 3 — The Web-App
**Stack:** Next.js 16 (App Router), TypeScript, Tailwind CSS v4, Zustand, TanStack Table, Sonner, Lucide-react

## 1. Architecture Overview

This phase delivers two things: (A) new read-only GET endpoints on the FastAPI orchestrator, and (B) completing the Next.js dashboard to consume them alongside the existing SSE stream.

### Data Flow

```
Browser <-> Next.js (port 3000)
              |-- Client components call api.* helpers
              |     -> fetch() to orchestrator (port 8001)
              |
              +-- /api/sse/[targetId]/route.ts (server-side proxy)
                    -> fetches orchestrator SSE with X-API-KEY header
                    -> re-streams events to browser via ReadableStream

Orchestrator (port 8001)
  |-- GET  /api/v1/targets            -> list all campaigns
  |-- GET  /api/v1/assets             -> assets by target_id
  |-- GET  /api/v1/vulnerabilities    -> vulns by target_id, filterable
  |-- GET  /api/v1/cloud_assets       -> cloud assets by target_id
  |-- GET  /api/v1/alerts             -> alerts by target_id, filterable
  |-- PATCH /api/v1/alerts/{id}       -> mark alert read
  |-- PATCH /api/v1/targets/{id}      -> update target profile
  +-- (existing) POST /targets, POST /control, GET /status, GET /stream/{id}
```

### State Management

Zustand campaign store hydrates from localStorage on load. If no persisted target, the home page fetches `GET /targets` and shows a campaign picker. Once a target is active, all pages read from the store and fetch target-scoped data.

### Key Principle

The orchestrator owns all DB access. The dashboard never connects to Postgres directly.

## 2. Orchestrator GET Endpoints

Seven new endpoints added to `orchestrator/main.py`, following existing patterns (async SQLAlchemy session, `X-API-KEY` auth, Pydantic response models).

### GET /api/v1/targets

- Returns all targets: `id`, `company_name`, `base_domain`, `created_at`
- No query params (campaign list is small)
- Used by: home page campaign picker, state recovery

### GET /api/v1/assets?target_id={int}

- `target_id` required
- Eager-loads `locations` relationship (ports/services needed for tree building)
- Returns flat list; the dashboard builds the tree client-side
- Used by: AssetTree hydration, Assets data table

### GET /api/v1/vulnerabilities?target_id={int}&severity={str}

- `target_id` required, `severity` optional filter
- Joins `assets` to include `asset_value` in response
- Used by: Vulnerabilities data table

### GET /api/v1/cloud_assets?target_id={int}

- `target_id` required
- Straight query, no joins
- Used by: Cloud data table

### GET /api/v1/alerts?target_id={int}&is_read={bool}

- `target_id` required, `is_read` optional filter
- Ordered by `created_at DESC`
- Used by: Alert dropdown

### PATCH /api/v1/alerts/{id}

- Body: `{ "is_read": true }`
- Used by: Alert dropdown "mark as read"

### PATCH /api/v1/targets/{id}

- Accepts partial `target_profile` updates (custom_headers, rate_limits)
- Merges into existing profile JSON, rewrites config files on disk
- Used by: Settings drawer

## 3. Bug Fixes in Existing Code

### src/types/schema.ts

- Add `"PAUSED"` and `"STOPPED"` to the `JobStatus` union type (orchestrator uses both since Phase 2 hardening)

### src/lib/api.ts

- Fix default `BASE_URL` from port `8000` to `8001` (matching docker-compose)
- Add `"unpause"` to the `controlWorker` action type
- Add new methods: `getTargets()`, `getAssets(targetId)`, `getVulnerabilities(targetId, severity?)`, `getCloudAssets(targetId)`, `getAlerts(targetId, isRead?)`, `markAlertRead(id)`, `updateTargetProfile(id, profile)`

### src/components/c2/WorkerConsole.tsx

- Add color entries for `PAUSED` (warning/yellow) and `STOPPED` (neutral/gray) to `STATUS_COLORS` and `STATUS_DOT`
- Add "Unpause" button (play icon) for jobs with `PAUSED` status, calling `api.controlWorker(name, "unpause")`

### src/hooks/useEventStream.ts

- Replace direct `EventSource` to orchestrator with connection to the new Next.js SSE proxy route (`/api/sse/${targetId}`)
- Remove the `api.sseUrl()` dependency

### src/components/c2/WorkerFeed.tsx

- Use the event's timestamp field instead of `new Date().toLocaleTimeString()` at render time

## 4. SSE Proxy Route

New file: `src/app/api/sse/[targetId]/route.ts`

### How It Works

1. Receives GET request from the browser
2. Reads `NEXT_PUBLIC_API_URL` and `NEXT_PUBLIC_API_KEY` from server-side env
3. Calls `fetch(${API_URL}/api/v1/stream/${targetId})` with `X-API-KEY` header
4. Returns a `new Response(ReadableStream)` with `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`
5. The ReadableStream pipes the orchestrator response body through chunk-by-chunk
6. On client disconnect, the fetch body is aborted via `AbortController`

### Why This Approach

- API key never reaches the browser
- Browser uses standard `EventSource` pointed at `/api/sse/123`
- Negligible latency (byte piping)
- Works identically in Docker and local dev

### Updated useEventStream.ts

- URL changes from `api.sseUrl(targetId)` to `/api/sse/${targetId}`
- All event listeners, 200-event buffer, and toast triggers remain unchanged

## 5. Home Page & Campaign Picker

### Behavior on Load

1. Check Zustand store for `activeTarget`
2. If found: show current dashboard home with campaign summary and quick-action cards (existing behavior)
3. If not found: call `api.getTargets()` and display results

### CampaignPicker Component

New file: `src/components/campaign/CampaignPicker.tsx`

- Card layout showing each target's `company_name`, `base_domain`, and `created_at`
- Clicking a campaign sets `activeTarget` in Zustand and navigates to `/campaign/c2`
- "New Campaign" card at the end links to `/campaign` (scope builder)
- If `getTargets()` returns empty, redirect straight to `/campaign`

### Campaign Switching

- Small dropdown in the `StatusBar` showing the active target's `base_domain`
- Clicking opens a lightweight picker to switch campaigns
- Switching updates the Zustand store, triggering all subscribed components to re-fetch

## 6. C2 Console Enhancements

### AssetTree — API Hydration + SSE Merge

- On mount, call `api.getAssets(targetId)` returning assets with eager-loaded `locations`
- Build tree hierarchy: domain -> subdomain -> IP (from locations) -> port/service -> endpoints -> params
- Store tree in local component state
- SSE `NEW_ASSET` events merge into existing tree (insert at correct depth, no full rebuild)
- Brief highlight/pulse on newly added nodes

### Settings Drawer

New file: `src/components/c2/SettingsDrawer.tsx`

- Triggered by gear icon button in C2 page header
- Slides in from right, 400px wide, overlay with backdrop
- Fields: Custom Headers (key-value pair inputs, add/remove rows), PPS rate limit (number input)
- On save, calls `PATCH /api/v1/targets/{id}` to update `target_profile`
- Close on save success or explicit close button

### StatusBoard

New file: `src/components/c2/StatusBoard.tsx`

- Sits below `PhaseProgress` bar on C2 page
- Reads from `job_state` data (fetched via `api.getStatus(targetId)`)
- For each RUNNING job: shows `container_name`, `current_phase`, and `last_tool_executed` as a chip/tag
- SSE `TOOL_PROGRESS` events update `last_tool_executed` in Zustand jobs array
- Simple grid layout, one row per active worker with pulse dot

### PhaseProgress Enhancement

- Wire to actual `current_phase` from highest-priority running job rather than static value

## 7. Data Tables & Findings Pages

All three pages use the existing `DataTable` component (TanStack Table wrapper with search, sort, pagination at 25 rows/page).

### Assets Page (/campaign/assets)

- On mount, call `api.getAssets(targetId)`
- Columns: `asset_type` (badge), `asset_value`, `source_tool`, `created_at`
- Filter dropdown for `asset_type` (subdomain, ip, cidr, url)

### Cloud Page (/campaign/cloud)

- On mount, call `api.getCloudAssets(targetId)`
- Columns: `provider` (colored badge), `asset_type`, `url` (clickable), `is_public` (boolean badge), `created_at`
- Filter dropdown for `provider`

### Vulns Page (/campaign/vulns)

- On mount, call `api.getVulnerabilities(targetId)`
- Columns: `severity` (colored badge), `title`, `asset_value` (joined), `source_tool`, `created_at`
- Filter tabs: All, Critical, High, Medium, Low, Info
- Clicking a row expands inline detail panel showing `description` and `poc`

### Shared Pattern

Each page reads `activeTarget` from Zustand. If no target, redirect to home. Simple loading/error/data state — no React Query or SWR needed for read-once views.

## 8. Alert System

### AlertDropdown Component

New file: `src/components/layout/AlertDropdown.tsx`

- Bell icon in `StatusBar`, next to connection indicator
- Unread count badge (red circle with number) from `api.getAlerts(targetId, isRead: false)` on mount and after each SSE `CRITICAL_ALERT`
- Dropdown panel (max 300px tall, scrollable) on click
- Each alert row: severity dot, `alert_type`, truncated `message`, relative timestamp
- "Mark as read" per alert calls `api.markAlertRead(id)` and decrements badge
- Existing SSE toast behavior stays (dropdown for review, toasts for live notification)

## 9. File Inventory & Build Order

### Step 1 — Orchestrator Endpoints

| File | Action |
|------|--------|
| `orchestrator/main.py` | Add 7 endpoints |

### Step 2 — Dashboard Bug Fixes

| File | Action |
|------|--------|
| `dashboard/src/types/schema.ts` | Add PAUSED, STOPPED to JobStatus |
| `dashboard/src/lib/api.ts` | Fix port, add unpause, add new API methods |

### Step 3 — SSE Proxy

| File | Action |
|------|--------|
| `dashboard/src/app/api/sse/[targetId]/route.ts` | New file |
| `dashboard/src/hooks/useEventStream.ts` | Point to proxy |

### Step 4 — Layout Enhancements

| File | Action |
|------|--------|
| `dashboard/src/components/layout/AlertDropdown.tsx` | New file |
| `dashboard/src/components/layout/StatusBar.tsx` | Add alert dropdown + campaign switcher |
| `dashboard/src/components/c2/WorkerConsole.tsx` | PAUSED/STOPPED fixes |
| `dashboard/src/components/c2/WorkerFeed.tsx` | Timestamp fix |

### Step 5 — Campaign Picker

| File | Action |
|------|--------|
| `dashboard/src/components/campaign/CampaignPicker.tsx` | New file |
| `dashboard/src/app/page.tsx` | Integrate picker with state recovery |

### Step 6 — C2 Enhancements

| File | Action |
|------|--------|
| `dashboard/src/components/c2/AssetTree.tsx` | API hydration + SSE merge |
| `dashboard/src/components/c2/SettingsDrawer.tsx` | New file |
| `dashboard/src/components/c2/StatusBoard.tsx` | New file |
| `dashboard/src/app/campaign/c2/page.tsx` | Add StatusBoard + SettingsDrawer |

### Step 7 — Data Tables

| File | Action |
|------|--------|
| `dashboard/src/app/campaign/assets/page.tsx` | Wire to API |
| `dashboard/src/app/campaign/cloud/page.tsx` | Wire to API |
| `dashboard/src/app/campaign/vulns/page.tsx` | Wire to API |

### Step 8 — Store Updates

| File | Action |
|------|--------|
| `dashboard/src/stores/campaign.ts` | Add alerts count, jobs refresh helpers |

**Total: 8 modified files, 5 new files. No new dependencies.**
