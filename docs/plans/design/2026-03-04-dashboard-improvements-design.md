# Dashboard Improvements Design

**Date:** 2026-03-04
**Status:** Draft
**Scope:** C2 Dashboard (Phase 3) — UX, Intelligence, Functionality

## Context

The C2 dashboard is a fully functional Phase 3 interface with 7 pages, 11 components, real-time SSE streaming, and typed API integration. All core features work, but data is presented raw without actionable insights, workflows are read-only, and there are several UX gaps for a solo bug bounty hunter who needs speed and information density.

## Operator Profile

- Solo bug bounty hunter
- Prioritizes speed, keyboard-driven workflows, and information density
- Needs the dashboard to answer "what should I look at next?" without clicking through multiple pages

---

## 1. Operational Intelligence

### 1.1 Campaign Overview Dashboard

Replace the current C2 page layout with a three-zone overview:

**Zone A — Stats Strip (top row)**

Four metric cards in a horizontal row:

| Card | Content |
|------|---------|
| Assets | Total count + breakdown by type (domains, IPs, endpoints) |
| Vulnerabilities | Count per severity, color-coded badges (critical red, high orange, medium yellow, low blue, info gray) |
| Cloud Exposure | Public-facing cloud asset count, highlighted when > 0 |
| Workers | Active worker count + current phase (RECON / VULN / EXPLOIT) with progress indicator |

Each card is clickable — navigates to the relevant detail page.

**Zone B — Prioritized Action Queue (center, main focus)**

A card-based vertical list occupying the primary viewport. Each card contains:

- **Title**: Human-readable finding summary (e.g., "Critical XSS on `app.target.com/login`")
- **Context**: Severity badge + confidence + discovery tool + timestamp
- **Actions**: View details button, mark-as-reviewed button, dismiss-as-false-positive button

Sorting logic (top to bottom):
1. Critical vulnerabilities not yet reviewed
2. High-severity vulnerabilities not yet reviewed
3. High-value assets (wildcard domains, public cloud resources) without deep scans
4. Newly discovered subdomains with open ports
5. Medium/low findings

The queue functions as a "bug bounty inbox" — the hunter works through it top to bottom. Items move to a "reviewed" section when actioned. The queue re-derives from live data on each page load.

**Zone C — Attack Surface Map (below action queue)**

A force-directed graph visualization of the discovered attack surface:

- **Node types**:
  - Domain (large circle, blue)
  - Subdomain (medium circle, cyan)
  - IP address (medium circle, gray)
  - Port/service (small circle, white)
  - Vulnerability (small diamond, color = severity)

- **Edges**: Domain → subdomain → resolved IP → open port → associated vulnerability

- **Interactions**:
  - Hover: Tooltip with node details
  - Click: Highlight the selected node's full branch
  - Double-click: Navigate to the finding detail
  - Zoom/pan: Standard canvas controls

- **Visual encoding**:
  - Nodes with critical vulns: Red glow/border
  - Nodes with high vulns: Orange glow/border
  - Clean nodes: Default gray
  - Dense clusters indicate high-value investigation targets

- **Implementation**: `react-force-graph-2d` (lightweight, canvas-based, handles hundreds of nodes). Data reshaped from the existing asset/vuln API responses — no new backend endpoints needed.

### 1.2 Discovery Timeline

An area chart (placed in the stats strip or as a collapsible panel) showing asset count over time. Purpose: detect when recon has plateaued (no new assets), signaling it's time to move to the next phase.

Data source: Asset `discovered_at` timestamps, bucketed by hour or day.

Implementation: Lightweight chart library — `recharts` (already React-friendly, small bundle).

---

## 2. UX & Visual Polish

### 2.1 Loading & Empty States

**Skeleton loaders** replace bare spinners on:
- Data tables (skeleton rows with pulsing placeholders)
- Stats cards (skeleton rectangles)
- Asset tree (skeleton tree structure)

**Contextual empty states** with:
- Descriptive message ("No assets yet — start a recon phase")
- One-click action button (e.g., "Launch Recon" or "Create Campaign")

### 2.2 Keyboard Shortcuts

Global shortcuts for navigation and table interaction:

| Shortcut | Action |
|----------|--------|
| `g then c` | Go to C2 Console |
| `g then a` | Go to Assets |
| `g then v` | Go to Vulns |
| `g then o` | Go to Overview |
| `j` / `k` | Navigate table rows down/up |
| `Enter` | Expand selected row |
| `x` | Toggle tag/mark on selected row |
| `Esc` | Close drawer/modal/overlay |
| `?` | Show keyboard shortcut overlay |
| `/` | Focus search input |

Implementation: A global `useKeyboardShortcuts` hook registered in the root layout. Shortcut overlay is a modal triggered by `?`.

### 2.3 Micro-interactions

- **SSE highlight**: New rows arriving via SSE get a brief yellow highlight flash (fade over 2s)
- **Status pulse**: Active worker cards pulse subtly (already partially implemented)
- **Severity badges**: Gentle scale-in animation on render
- **Page transitions**: Quick opacity fade on content area (150ms)
- **Drawer slide**: Settings drawer slides in with a 200ms ease-out

### 2.4 Information Density

- **Compact table mode**: Toggle in settings — reduces row height and font size for more rows visible
- **Icon-only sidebar**: Sidebar collapses to icons on narrow viewports or via toggle (partially exists, enhance)
- **Inline hover previews**: Hovering a vuln row shows a tooltip with first 2 lines of description + PoC snippet

### 2.5 Theme Toggle (Dark / Light)

- Add a theme toggle to the StatusBar (sun/moon icon) and Settings page
- Light theme CSS variables defined in `globals.css` alongside existing obsidian dark theme
- Theme preference persisted in localStorage via the Zustand UI store
- Use CSS custom properties switching (class `dark` / `light` on `<html>`) — Tailwind v4 supports this natively

Light theme palette (complementary to obsidian):
- Background: `#ffffff`
- Surface: `#f6f8fa`
- Text: `#1f2328`
- Accent: `#0969da`
- Border: `#d1d9e0`
- Success/Danger/Warning: Same hues, adjusted for light background contrast

---

## 3. Functionality Gaps

### 3.1 Settings Page (`/settings`)

A new route with sections:

- **Connection**: Orchestrator URL, API key (editable, validated on save)
- **Defaults**: Default rate limits and custom headers for new campaigns
- **Appearance**: Theme toggle, compact mode toggle, sidebar behavior
- **Shortcuts**: Keyboard shortcut reference (read-only display)

### 3.2 Findings Workflow

Per-row actions on all data tables:

- **Tag**: Dropdown to apply tags (e.g., "interesting", "follow-up", "out-of-scope", custom)
- **False positive**: Marks finding as FP — removes from action queue and severity counts, shows in a separate "dismissed" view
- **Notes**: Free-text annotation per finding (inline editable, saved via API or localStorage)
- **Reviewed**: Mark a finding as reviewed (used by the action queue to de-prioritize)

State: Initially backed by localStorage keyed to finding ID. Can migrate to API endpoints when backend supports it.

### 3.3 Export & Reporting

Export button on each data table + a global "Export Campaign" option:

- **Markdown**: Formatted for bug bounty submission (title, severity, description, PoC, affected URL)
- **JSON**: Raw structured data for piping into other tools
- **Filtered**: Exports respect current table filters (e.g., "only critical + high")

Global campaign export aggregates all findings into a single report with table of contents.

### 3.4 Advanced Filtering

Extend all data tables with a filter bar:

- **Assets**: Type (domain/IP/endpoint/wildcard), source tool, date range
- **Vulns**: Severity (existing), source tool, CVSS range, date range
- **Cloud**: Provider (AWS/Azure/GCP), public/private, resource type

Filters are composable (AND logic) and persist within the session via Zustand.

### 3.5 Worker Log Drill-down

Click a worker card in StatusBoard or WorkerConsole to open a terminal-like log pane:

- Full container stdout/stderr in a monospace, scrollable view
- Auto-scroll to bottom with a "pin to bottom" toggle
- Log level color-coding (ERROR = red, WARN = yellow, INFO = default)
- Requires a new backend endpoint: `GET /api/v1/workers/{container}/logs`

---

## 4. Component Architecture

### New Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `OverviewDashboard` | `components/overview/` | Main overview layout (stats + queue + map) |
| `StatsStrip` | `components/overview/` | Row of metric cards |
| `ActionQueue` | `components/overview/` | Prioritized action card list |
| `AttackSurfaceMap` | `components/overview/` | Force-directed graph canvas |
| `DiscoveryTimeline` | `components/overview/` | Area chart for asset discovery over time |
| `KeyboardShortcuts` | `components/common/` | Global shortcut handler + overlay modal |
| `SkeletonTable` | `components/common/` | Table skeleton loader |
| `SkeletonCard` | `components/common/` | Card skeleton loader |
| `EmptyState` | `components/common/` | Reusable empty state with action button |
| `FindingActions` | `components/findings/` | Tag/FP/notes/review action buttons per row |
| `ExportMenu` | `components/findings/` | Export dropdown (markdown/JSON/filtered) |
| `FilterBar` | `components/findings/` | Composable filter controls |
| `WorkerLogPane` | `components/c2/` | Terminal-style log viewer |
| `ThemeToggle` | `components/layout/` | Sun/moon theme switch |
| `SettingsPage` | `app/settings/` | Settings route |

### Modified Components

| Component | Changes |
|-----------|---------|
| `DataTable` | Add skeleton loading state, row selection, hover preview, keyboard nav, filter bar slot |
| `StatusBar` | Add theme toggle icon |
| `Sidebar` | Add overview link, icon-only collapse enhancement |
| `campaign.ts` (store) | Add theme preference, filter state, reviewed/tagged finding IDs |
| `ui.ts` (store) | Add compactMode, theme |
| `api.ts` | Add worker logs endpoint, export helpers |

### New Dependencies

| Package | Purpose | Bundle Impact |
|---------|---------|---------------|
| `react-force-graph-2d` | Attack surface map | ~45KB gzipped |
| `recharts` | Discovery timeline + severity chart | ~55KB gzipped |

No other new dependencies — keyboard shortcuts, skeletons, theme toggle, export all use existing primitives (React hooks, Tailwind CSS, native APIs like `Blob` + `URL.createObjectURL`).

---

## 5. Data Flow

### Action Queue Derivation

```
GET /api/v1/vulnerabilities?target_id={id} → filter unreviewed → sort by severity
GET /api/v1/assets?target_id={id}         → filter high-value unscanned → sort by recency
                                           → merge into single prioritized list
```

Reviewed/FP state is tracked client-side (localStorage set of finding IDs). No backend changes needed for v1.

### Attack Surface Map Data

```
GET /api/v1/assets?target_id={id} → build node list (domains, subs, IPs, ports)
GET /api/v1/vulnerabilities?target_id={id} → attach vuln nodes to port/asset nodes
                                            → generate edge list
                                            → feed to react-force-graph-2d
```

Same reshape logic as the existing AssetTree but outputting `{ nodes: [], links: [] }` instead of a tree.

### Theme Switching

```
Zustand ui store → theme: 'dark' | 'light'
→ <html className={theme}>
→ CSS variables switch via .dark / .light selectors in globals.css
→ localStorage persistence
```

---

## 6. Implementation Priority

Ordered by impact for a solo bug bounty hunter:

| Priority | Feature | Effort |
|----------|---------|--------|
| P0 | Campaign Overview (stats strip + action queue) | Medium |
| P0 | Keyboard shortcuts | Small |
| P1 | Attack surface map | Medium |
| P1 | Findings workflow (tag/FP/notes/review) | Medium |
| P1 | Theme toggle (dark/light) | Small |
| P2 | Export & reporting | Small |
| P2 | Advanced filtering | Medium |
| P2 | Settings page | Small |
| P2 | Discovery timeline chart | Small |
| P3 | Skeleton loaders & empty states | Small |
| P3 | Micro-interactions & animations | Small |
| P3 | Compact table mode & density options | Small |
| P3 | Worker log drill-down | Medium (needs backend) |
| P3 | Inline hover previews | Small |
