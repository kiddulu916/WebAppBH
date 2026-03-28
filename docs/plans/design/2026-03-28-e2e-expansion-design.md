# E2E Test Suite Expansion — Design Document

**Date:** 2026-03-28
**Scope:** New pages, deeper coverage, cross-cutting flows, removals

---

## 1. Overview

Expand the e2e test suite from 10 files / ~20 tests to 21 files / ~70 tests. Build three new dashboard pages, remove two unused pages, add edge case coverage across all existing pages, and add five cross-cutting multi-page flow tests.

**Desktop-only** — no mobile/responsive testing.

---

## 2. Removals

### `/campaign/compare` — Target Comparison
Delete entirely. No practical use case identified. Remove page file, nav links, and any supporting components.

### `/campaign/explorer` — Asset Explorer
Delete entirely. All tree-browsing functionality is absorbed into the new assets page's expandable row "Tree view" tab.

---

## 3. New Pages

### 3.1 Asset Inventory (`/campaign/assets`)

**Layout:** Full-width TanStack Table with expandable row detail panels.

**Table columns:**
- Hostname/IP (primary identifier)
- Type (subdomain, IP, CIDR)
- Ports (comma-separated, truncated with "+N more")
- Vuln Count (badge, color-coded by highest severity)
- Cloud Resources (count)
- First Seen / Last Seen (relative timestamps)
- Status (active, stale, out-of-scope)

**Expandable row panel** (inline below the row):
- **Locations tab** — Ports, protocols, HTTP status, response size
- **Vulnerabilities tab** — Mini-table with severity, type, status
- **Cloud tab** — Associated S3 buckets, Azure blobs, etc.
- **Tree view tab** — Hierarchical breakdown (replaces explorer): target → domain → subdomain → IPs → ports

**Interactions:**
- Column sorting, multi-column filtering (type, severity, date range)
- Text search across hostname/IP
- Bulk select + bulk actions (rescan selected, export CSV)
- Click vuln count badge → findings page pre-filtered for that asset
- Server-side pagination (50 per page)

**Empty state:** Illustration + "No assets discovered yet. Create a target and run a scan to start discovering assets."

**API failure:** Table skeleton with retry button + toast explaining the error.

**Data source:** `GET /api/v1/assets?target_id=X` with pagination params, plus expand-on-demand calls for locations/vulns/cloud per asset.

---

### 3.2 Workflow Builder (`/campaign/flow`)

**Layout:** Two-panel split — left panel is playbook configurator, right panel is live execution monitor.

**Left Panel — Playbook Configurator:**
- Dropdown to select predefined playbook (Quick Scan, Deep Recon, API-Focused, Cloud Audit, Full Pipeline)
- Each playbook displays stages as an ordered list of cards
- Each stage card shows: name, tools included, estimated duration, on/off toggle
- Expandable stage cards reveal per-tool parameter controls (timeout, threads, wordlist selection)
- "Save as Custom Playbook" button — names and persists the configuration
- "Apply to Target" button — target dropdown, pushes config to `shared/config/{target_id}/playbook.json`

**Right Panel — Live Execution Monitor:**
- Target selector dropdown at top
- Vertical timeline of pipeline stages for selected target
- Each stage shows: status icon (pending/running/completed/failed), name, start time, duration, tool count
- Running stages pulse with animated indicator
- Clicking a stage expands to show per-tool status: tool name, status, output line count, last log line
- Failed stages show error summary with "View Full Logs" link (opens C2 console filtered to that tool)
- Auto-updates via SSE — new events update stage/tool statuses in real time

**Empty states:**
- No playbook selected: "Select a playbook to configure your scan pipeline"
- No executions yet: "No scans running. Apply a playbook to a target to begin."
- No target selected in monitor: "Select a target to view execution progress"

**API failure:** Configurator shows last-known state with stale-data banner. Monitor shows "Connection lost, retrying..." with manual retry button.

---

### 3.3 Attack Graph (`/campaign/graph`)

**Layout:** Full-screen canvas with floating control panel (top-right) and detail sidebar (slides in from right on node click).

**Graph Layer — Asset Relationships (always visible):**
- Nodes represent assets (subdomains, IPs, cloud resources) — shaped/colored by type
- Edges represent relationships: "subdomain of", "resolves to", "runs on", "hosts", "stores data in"
- Node size scales with vuln count
- Labels show hostname/IP, truncated to fit
- Standard interactions: zoom, pan, drag nodes, fit-to-view

**Overlay Layer — Attack Paths (toggle on/off):**
- Directed edges highlighted in red/orange showing exploitable chains
- Each path gets a severity score (highest vuln in chain)
- Multiple paths shown simultaneously, distinguished by color intensity
- Toggle panel lists discovered paths with severity; click one to highlight and dim rest

**Floating Control Panel:**
- Target selector dropdown
- "Show Attack Paths" toggle
- Filter by asset type (checkboxes: subdomains, IPs, cloud)
- Filter by minimum severity (slider: info → critical)
- Layout algorithm selector (force-directed, hierarchical, radial)
- "Fit to View" and "Reset Layout" buttons

**Detail Sidebar (on node click):**
- Asset details: hostname, IP, type, first/last seen
- Ports and services list
- Vulnerability summary with severity breakdown
- Connected nodes list (click to navigate)
- "View in Assets" link → assets page with that row expanded

**Empty state:** Centered: "No assets to graph. Run a scan to populate the attack surface."

**API failure:** Graph freezes with "Connection lost" overlay, retains last-known state, retry button.

**Library:** React Flow — React-native, built-in zoom/pan/drag, custom node components, integrates with Zustand.

---

## 4. New API Endpoints

### For `/campaign/flow`:
- `GET /api/v1/playbooks` — List predefined playbooks
- `GET /api/v1/playbooks/{playbook_id}` — Playbook detail (stages, tools, default params)
- `POST /api/v1/playbooks` — Save custom playbook
- `POST /api/v1/targets/{target_id}/apply-playbook` — Apply playbook config to target
- `GET /api/v1/targets/{target_id}/execution` — Current pipeline execution state

### For `/campaign/graph`:
- `GET /api/v1/targets/{target_id}/graph` — Nodes + edges for asset relationship graph
- `GET /api/v1/targets/{target_id}/attack-paths` — Attack path chains with severity scores

### For `/campaign/assets` (expandable rows):
- `GET /api/v1/assets/{asset_id}/locations` — Locations for a specific asset
- `GET /api/v1/assets/{asset_id}/vulnerabilities` — Vulns for a specific asset
- `GET /api/v1/assets/{asset_id}/cloud` — Cloud resources for a specific asset
- Modify `GET /api/v1/assets` to support `page` and `per_page` params

### Test seed extensions (`POST /api/v1/test/seed`):
- Playbook fixture data (one predefined playbook, 3 stages)
- Execution state fixtures (stages: pending, running, completed, failed)
- Graph relationship data (edges between seeded assets)
- Attack path fixture (chain of 2 vulns across 2 assets)

---

## 5. Edge Case & Error Handling Tests

### Empty States (`empty-states.spec.ts`)
One test per page: navigate with no seeded data, verify empty state message renders (not broken layout or stuck spinner). Pages: targets, c2-console, findings, bounties, schedules, assets, flow, graph.

### API Errors (`api-errors.spec.ts`)
Use `page.route()` to intercept API calls and return error responses:
- 500 on target list → error state with retry button
- 500 on assets fetch → error skeleton with retry
- Network timeout on SSE → "Connection lost" banner, reconnect on retry
- 404 on nonexistent target → "not found" messaging
- Verify no white screens, no unhandled promise rejections in console

### Boundary Conditions (`edge-cases.spec.ts`)
- Special characters in company name (`O'Reilly & Co. <test>`) → proper escaping
- Very long domain (60+ chars) → table doesn't break layout
- 100+ seeded assets → pagination works, footer counts correct
- Rapid double-click on submit → no duplicate creation
- Fast typing in command palette → debounced search doesn't crash

### Existing Page Depth (additions to current test files)
- `findings-browser`: zero findings empty state, filter returning no results
- `bounty-tracking`: bounty with zero payout, special chars in notes
- `schedule-scan`: invalid cron expression → validation error
- `worker-control`: all three actions (pause/resume/stop) reflect in UI state

---

## 6. Cross-Cutting Flow Tests

### `flows/recon-lifecycle.spec.ts` — Full Recon Lifecycle
Create target via wizard → navigate to flow → select playbook → apply → trigger rescan → C2 shows running jobs via SSE → assets page shows discoveries → findings show vulns → create bounty → verify on bounties page → cleanup.

### `flows/triage-workflow.spec.ts` — Triage Workflow
Seed target + vulns → findings → filter critical → correlation view → create bounty → update status to "submitted" → update payout → verify persistence on reload.

### `flows/operational-control.spec.ts` — Operational Control
Seed target + running jobs → C2 → verify RUNNING → pause worker → verify PAUSED → resume → verify RUNNING → stop → verify STOPPED → timeline reflects each state change in order.

### `flows/configuration-flow.spec.ts` — Configuration Flow
Create target → settings → add custom headers → set rate limit → save → schedules → create daily schedule → verify in list → toggle off → verify disabled → settings → verify persistence.

### `flows/worker-monitoring.spec.ts` — Worker Execution & Progress
Create target → apply playbook → trigger rescan → flow page monitor: stages transition pending → running → completed → expand stage to see per-tool status → seed failure event → verify failed icon + error summary → "View Full Logs" navigates to C2 → C2 timeline matches flow page → emit SSE events → verify both pages update within 5s → intercept SSE to test disconnect/reconnect → after recon stage completes verify assets page shows discoveries → after vuln stage verify findings page shows vulns → cleanup.

---

## 7. Data-testid Attributes

### Assets Page
`assets-table`, `assets-search`, `assets-type-filter`, `assets-severity-filter`, `asset-row-{id}`, `asset-expand-btn-{id}`, `asset-detail-panel-{id}`, `asset-tab-locations`, `asset-tab-vulns`, `asset-tab-cloud`, `asset-tab-tree`, `asset-vuln-badge-{id}`, `assets-pagination`, `assets-bulk-select`, `assets-export-btn`, `assets-empty-state`, `assets-error-state`, `assets-retry-btn`

### Flow Page
`flow-playbook-select`, `flow-stage-card-{name}`, `flow-stage-toggle-{name}`, `flow-stage-expand-{name}`, `flow-tool-param-{name}`, `flow-save-playbook-btn`, `flow-apply-btn`, `flow-apply-target-select`, `flow-monitor-target-select`, `flow-monitor-stage-{name}`, `flow-monitor-tool-{name}`, `flow-monitor-status-{name}`, `flow-monitor-logs-link-{name}`, `flow-empty-config`, `flow-empty-monitor`, `flow-connection-lost`

### Graph Page
`graph-canvas`, `graph-target-select`, `graph-attack-paths-toggle`, `graph-filter-type-{type}`, `graph-severity-slider`, `graph-layout-select`, `graph-fit-btn`, `graph-reset-btn`, `graph-node-{id}`, `graph-detail-sidebar`, `graph-detail-close`, `graph-path-list`, `graph-path-item-{id}`, `graph-empty-state`, `graph-error-overlay`

### Existing Pages (additions)
`{page}-empty-state` and `{page}-error-state` + `{page}-retry-btn` on all pages that lack them.

---

## 8. Test File Organization

```
dashboard/e2e/tests/
├── assets-inventory.spec.ts          # New page tests
├── workflow-builder.spec.ts          # New page tests
├── attack-graph.spec.ts             # New page tests
├── api-errors.spec.ts               # Error handling
├── edge-cases.spec.ts               # Boundary conditions
├── empty-states.spec.ts             # Empty state per page
├── flows/
│   ├── recon-lifecycle.spec.ts      # Create → scan → find → bounty
│   ├── triage-workflow.spec.ts      # Findings → correlate → bounty
│   ├── operational-control.spec.ts  # Pause → resume → stop workers
│   ├── configuration-flow.spec.ts   # Settings → schedule → verify
│   └── worker-monitoring.spec.ts    # Worker execution → UI sync
├── bounty-tracking.spec.ts          # Existing + additions
├── c2-console.spec.ts               # Existing
├── command-palette.spec.ts          # Existing
├── create-campaign.spec.ts          # Existing
├── findings-browser.spec.ts         # Existing + additions
├── schedule-scan.spec.ts            # Existing + additions
├── settings-profile.spec.ts        # Existing
├── sse-live-updates.spec.ts        # Existing
├── target-management.spec.ts       # Existing
└── worker-control.spec.ts          # Existing + additions
```

---

## 9. Implementation Order

1. **Removals** — Delete compare + explorer pages, clean nav links
2. **Backend endpoints** — Playbook, graph, asset-detail, execution-state, seed extensions
3. **Assets page** — Build UI + tests
4. **Flow page** — Build UI + tests
5. **Graph page** — Build UI + tests
6. **Edge case tests** — Empty states, API errors, boundary conditions
7. **Existing page depth** — Additions to current test files
8. **Cross-cutting flows** — Multi-page journey tests

**Estimated total:** ~51 new tests across 11 new files, bringing the suite to ~70 tests across 21 files.
