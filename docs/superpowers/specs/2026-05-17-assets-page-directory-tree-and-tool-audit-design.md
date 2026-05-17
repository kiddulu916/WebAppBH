# Design: Assets Page Directory Tree, Pagination Fix, C2 Cleanup & Tool Audit

**Date:** 2026-05-17
**Status:** Approved

---

## Overview

Four coordinated workstreams:

1. **Directory hierarchy** — new `path_nodes` DB table populated as assets are discovered, feeding a tree UI
2. **Assets page** — fix 100-item pagination cap; replace inline expand panel with a full-page asset detail view showing a directory tree + ports panel + side-drawer
3. **C2 page cleanup** — remove `QueueHealthWidget` and `AssetTree`
4. **Tool audit** — full pass across all info_gathering stage tools: binary presence, invocation correctness, output parsing, and error surfacing

---

## Section 1: Schema & API

### 1.1 `path_nodes` table

```sql
CREATE TABLE path_nodes (
    id           SERIAL PRIMARY KEY,
    target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id     INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    parent_id    INTEGER REFERENCES path_nodes(id) ON DELETE CASCADE,
    path_segment TEXT NOT NULL,
    full_path    TEXT NOT NULL,
    node_type    TEXT,
    source_tool  TEXT,
    created_at   TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_path_nodes ON path_nodes(target_id, full_path);
CREATE INDEX idx_path_nodes_target ON path_nodes(target_id);
CREATE INDEX idx_path_nodes_parent ON path_nodes(parent_id);
CREATE INDEX idx_path_nodes_asset ON path_nodes(asset_id);
```

- `asset_id` nullable — intermediate directory nodes (inferred from child URL paths) have no corresponding `Asset` row
- `node_type` mirrors the `asset_type` of the linked Asset (e.g. `directory`, `file`, `sensitive_file`, `form`, `upload`)
- `full_path` is unique per target to prevent duplicate nodes

### 1.2 ORM model

Add `PathNode` model to `shared/lib_webbh/database.py` following the existing model pattern. Export from `shared/lib_webbh/__init__.py`.

### 1.3 Alembic migration

New migration in `shared/lib_webbh/alembic/` to create the `path_nodes` table and indexes.

### 1.4 `PathTreeBuilder` helper

New module `shared/lib_webbh/path_tree.py`:

- `PathTreeBuilder.upsert(target_id, asset_id, url, node_type, source_tool, session)` — parses the URL path, walks from root to leaf, upserts each segment into `path_nodes`, sets `asset_id` on the leaf node
- Intermediate nodes get `node_type="directory"` and `asset_id=None` unless a matching Asset row exists
- Called from `InfoGatheringTool.save_asset` for any asset whose `asset_value` starts with `http://` or `https://`
- Export `PathTreeBuilder` from `lib_webbh.__init__`

### 1.5 New orchestrator API endpoints

**`GET /api/v1/path_nodes`**
- Query params: `target_id` (required), `asset_id` (optional — scope to subtree rooted at this asset's node)
- Returns the tree as a nested JSON structure: `{ nodes: PathNodeTree[] }` where each node has `{ id, path_segment, full_path, node_type, asset_id, children: [] }`
- Builds the nested structure from the flat adjacency list server-side

**`GET /api/v1/path_nodes/{node_id}`**
- Returns single node detail: node fields + linked Asset row (type, scope_classification, source_tool, created_at) + linked Vulnerability count + linked Observation tech_stack

### 1.6 Pagination fix

`api.getAssets()` in `dashboard/src/lib/api.ts` currently sends no `page`/`page_size` params, receiving only the first 100 assets.

Fix: implement `getAllAssets(targetId)` that fetches pages sequentially at `page_size=500` until `fetched >= total`. The assets page calls `getAllAssets` instead of `getAssets` and shows a `Loading N / total…` indicator while pages are in flight.

---

## Section 2: Frontend Changes

### 2.1 Assets table (`/campaign/assets/page.tsx`)

- **Pagination**: replace `getAssets` call with `getAllAssets`; show `Loading N / total…` spinner while pages accumulate; render table only after all pages are loaded
- **Row click**: entire row becomes a `<Link href="/campaign/assets/[id]">` — clicking navigates to the detail page
- **Remove**: expand chevron column, `expandedRow` state, `activeTab` state, `detailLoading` state, `detailData` state, `handleExpand` handler, `AssetRowGroup` expand panel, all tab components (`LocationsTab`, `VulnerabilitiesTab`, `CloudTab`, `TreeTab`) — all detail now lives on the dedicated page
- **Keep**: search, type filter, scope filter, sort headers, bulk-select, bulk classify bar, pagination display (shows total count)

### 2.2 Asset detail page (`/campaign/assets/[id]/page.tsx`)

New route. Layout:

**Header**
- `← Assets` back link
- Asset value in monospace (e.g. `https://t-mobile.com/accessory/jbl-boombox-black`) — no type or scope badge

**Two-column body** (flex row, fills viewport height)
- Left: `DirectoryTree` component — full path tree for the asset's target, with the current asset's node pre-selected and expanded. Each node shows its `path_segment` and a small type badge. Nodes collapse/expand with a chevron.
- Right: `PortsList` component — fixed width (`w-56`), lists all `Location` rows for this asset. Each port row shows port number, protocol, service, state badge. Port rows are clickable.

**Side-drawer** (`AssetNodeDrawer` component)
- Slides in from the right edge (fixed position, z-indexed above content)
- Triggered by clicking a tree node or a port row
- Close button (X) and click-outside dismiss
- *Tree node content*: type badge, scope classification badge, source tool, discovered timestamp, linked vuln count (colored by highest severity), tech observations if present
- *Port content*: port number, protocol, service, state badge, banner text if available in the Location row

### 2.3 C2 page (`/campaign/c2/page.tsx`)

Remove:
- The `col-span-1` Asset Tree block and the surrounding `grid grid-cols-3` wrapper — Campaign Timeline promoted to full width in its own `div`
- `<QueueHealthWidget />` and its import
- `AssetTree` import and component
- `AssetDetailDrawer` import and component
- `buildTree` function
- `handleAssetSelect` callback
- `allAssets` state
- `treeRoots` state
- `selectedAsset` state
- The `useEffect` that calls `api.getAssets` to populate the tree
- The `NEW_ASSET` branch inside the SSE merge `useEffect` (the branch that pushes into `treeRoots`); the `KILL_ALL`, `RERUN_STARTED`, and `CLEAN_SLATE` branches in that same effect must be kept as they drive job state resets

Keep: Pipeline Grid, Worker Job Cards, Campaign Timeline (full width), System Pulse (full width or paired with Diff Timeline), Diff Timeline, Scope Drift Alerts.

---

## Section 3: Worker Tool Audit

### 3.1 Audit criteria (per tool)

For every tool across all 12 pipeline stages:

1. **Binary present** — `Dockerfile.info_gathering` installs the executable (or it's a Python package import)
2. **Invocation correct** — CLI flags match the binary's current interface; output format flag (e.g. `-json`) matches what the parser expects
3. **Output parsed & saved** — stdout is correctly parsed and `save_asset` / `save_observation` / `save_location` is called with the right types; no discovered data silently dropped
4. **Errors surface** — exceptions are caught and logged with `self.log.error(...)` including the tool name and error string; no bare `return` after a silent `except`

### 3.2 PathTreeBuilder wiring

After the audit, every `save_asset` call for a URL-valued asset triggers `PathTreeBuilder.upsert`. This is the point where the directory hierarchy is populated as tools run.

### 3.3 Tools in scope (all stages)

Stage 1 (`search_engine_recon`): `DorkEngine`, `ArchiveProber`, `CacheProber`, `ShodanSearcher`, `CensysSearcher`, `SecurityTrailsSearcher`

Stage 2 (`web_server_fingerprint`): `LivenessProbe`, `BannerProbe`, `HeaderOrderProbe`, `MethodProbe`, `ErrorPageProbe`, `TLSProbe`, `WAFProbe`, `WhatWeb`

Stage 3 (`web_server_metafiles`): `MetafileParser`, `MetaTagAnalyzer`

Stage 4 (`enumerate_applications`): `Subfinder`, `Assetfinder`, `AmassPassive`, `AmassActive`, `Massdns`, `VHostProber`, `Naabu`, `AppPathEnumerator`, `CTLogSearcher`

Stage 5 (`review_comments`): `CommentHarvester`, `MetadataExtractor`, `JsSecretScanner`, `SourceMapProber`, `RedirectBodyInspector`

Stage 6 (`identify_entry_points`): `FormMapper`, `Paramspider`, `Httpx`, `WebSocketProber`

Stage 7 (`aggregate_entry_points`): `EntryPointAggregator`

Stage 8 (`map_execution_paths`): `Katana`, `Hakrawler`

Stage 9 (`review_comments_deep`): same tools as Stage 5

Stage 10 (`fingerprint_framework`): `Wappalyzer`, `CookieFingerprinter`, `Webanalyze`, `HeaderFrameworkProbe`, `MetaGeneratorProbe`, `FrameworkFileProber`

Stage 11 (`map_architecture`): `Waybackurls`, `ArchitectureModeler`

Stage 12 (`map_application`): `ApplicationMapper`, `AttackSurfaceAnalyzer`

### 3.4 Known pre-audit signals

- `Subfinder`, `Assetfinder` — code is correct but exceptions silenced; need install verification + error logging
- `AmassPassive`, `AmassActive` — JSON output format is version-sensitive; verify `-json` flag output shape matches parser
- `Massdns` — requires a resolvers file at a known path; verify it is present in the container
- `Naabu` — saves `Location` rows (ports), not `Asset` rows; verify wiring is to `save_location` / `save_observation`, not `save_asset`
- All tools — the 100-item API cap was hiding saved assets; many "missing" subdomains are likely in DB already

---

## Section 4: Testing

### 4.1 Live browser testing (post-implementation)

Using Playwright browser automation against the running stack:

1. Assets table — verify all assets load (not capped at 100), loading indicator shown during fetch, filters/sort work, row click navigates to detail page
2. Asset detail page — directory tree renders for a URL asset, nodes expand/collapse, clicking a node opens the side-drawer with type/scope/tool data, clicking a port opens port drawer
3. C2 page — QueueHealthWidget and AssetTree absent, Campaign Timeline full width, no console errors
4. Console error recording via `read_console_messages` throughout all interactions
5. GIF recording of the asset detail page interaction flow

### 4.2 Backend verification

- `pytest tests/e2e/ --e2e -v` for regression check
- `docker logs webbh-info-gathering` during a scan run to verify tool errors are logged
- Direct DB query on `path_nodes` after a scan to verify population

---

## Constraints & notes

- `path_nodes` is append-only during a scan; deduplication is handled by the unique index on `(target_id, full_path)`
- The `PathTreeBuilder` must be async and use the existing `get_session` context manager
- No changes to `PIPELINE_STAGES` in `playbooks.py` or `WORKER_STAGES` in `worker-stages.ts` — this feature does not add or rename pipeline stages
- The three-layer coherence rule is not triggered by this work
- Asset detail page requires the orchestrator to be running; if `path_nodes` is empty (no scan yet), show an empty-state message in the tree panel
