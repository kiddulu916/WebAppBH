# Assets Page Directory Tree, Pagination Fix, C2 Cleanup & Tool Audit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `path_nodes` directory-hierarchy table populated as assets are discovered, build a full-page asset detail view with a directory tree + ports panel + side-drawer, fix the 100-asset pagination cap, clean up the C2 page, and audit/fix all 40+ info_gathering tools.

**Architecture:** A new `PathNode` ORM model and `PathTreeBuilder` helper (in `lib_webbh`) populate the hierarchy table whenever `save_asset` is called with a URL-valued asset. Two new orchestrator endpoints serve the tree. The dashboard gains an `/campaign/assets/[id]` detail page with a `DirectoryTree` + `PortsList` layout. The tool audit fixes missing Docker installs, wrong method calls, and silent exception swallowing across all 12 stages.

**Tech Stack:** Python/SQLAlchemy (async), Alembic, FastAPI, Next.js 16 / React 19 / Tailwind v4, Lucide icons, TypeScript

---

## File Map

**New files:**
- `shared/lib_webbh/path_tree.py` — PathTreeBuilder helper
- `shared/lib_webbh/alembic/versions/002_add_path_nodes.py` — migration
- `dashboard/src/app/campaign/assets/[id]/page.tsx` — asset detail page
- `dashboard/src/components/assets/DirectoryTree.tsx` — collapsible tree component
- `dashboard/src/components/assets/PortsList.tsx` — ports panel component
- `dashboard/src/components/assets/AssetNodeDrawer.tsx` — slide-in detail drawer
- `workers/info_gathering/resolvers.txt` — DNS resolvers for massdns
- `tests/unit/test_path_tree.py` — PathTreeBuilder unit tests

**Modified files:**
- `shared/lib_webbh/database.py` — add PathNode model
- `shared/lib_webbh/__init__.py` — export PathNode, PathTreeBuilder
- `orchestrator/main.py` — add /api/v1/path_nodes endpoints
- `dashboard/src/lib/api.ts` — add getAllAssets(), path_nodes calls
- `dashboard/src/app/campaign/assets/page.tsx` — remove expand panel, add row navigation, fix pagination
- `dashboard/src/app/campaign/c2/page.tsx` — remove AssetTree, QueueHealthWidget, related state
- `workers/info_gathering/base_tool.py` — wire PathTreeBuilder in save_asset
- `docker/Dockerfile.info_gathering` — install amass, wappalyzer, webanalyze, ffuf
- `workers/info_gathering/tools/naabu.py` — fix save_location wiring
- `workers/info_gathering/tools/vhost_prober.py` — fix save_observation wiring
- `workers/info_gathering/tools/subfinder.py` — add error logging
- `workers/info_gathering/tools/assetfinder.py` — add error logging
- `workers/info_gathering/tools/amass_passive.py` — add error logging
- `workers/info_gathering/tools/amass_active.py` — add error logging
- `workers/info_gathering/tools/waybackurls.py` — add error logging
- `workers/info_gathering/tools/massdns.py` — add error logging
- `workers/info_gathering/tools/wappalyzer.py` — add error logging
- `workers/info_gathering/tools/webanalyze.py` — add error logging
- (remaining tool files audited and fixed inline per task)

---

## Task 1: Add PathNode ORM model

**Files:**
- Modify: `shared/lib_webbh/database.py` (after the `Asset` class, ~line 266)
- Modify: `shared/lib_webbh/__init__.py` (exports block, ~line 26)

- [ ] **Step 1: Add PathNode class to database.py after the Asset class**

Open `shared/lib_webbh/database.py`. After the closing of the `Asset` class (after line ~266, the `api_schemas` relationship), add:

```python
class PathNode(TimestampMixin, Base):
    """Directory/file hierarchy node derived from URL-valued assets."""

    __tablename__ = "path_nodes"
    __table_args__ = (
        UniqueConstraint("target_id", "full_path", name="uq_path_nodes_target_path"),
        Index("idx_path_nodes_target", "target_id"),
        Index("idx_path_nodes_parent", "parent_id"),
        Index("idx_path_nodes_asset", "asset_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id", ondelete="CASCADE"))
    asset_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    parent_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("path_nodes.id", ondelete="CASCADE"), nullable=True
    )
    path_segment: Mapped[str] = mapped_column(Text, nullable=False)
    full_path: Mapped[str] = mapped_column(Text, nullable=False)
    node_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    target: Mapped["Target"] = relationship("Target")
    asset: Mapped[Optional["Asset"]] = relationship("Asset")
    parent: Mapped[Optional["PathNode"]] = relationship(
        "PathNode", remote_side="PathNode.id", back_populates="children"
    )
    children: Mapped[list["PathNode"]] = relationship(
        "PathNode", back_populates="parent", cascade="all, delete-orphan"
    )
```

- [ ] **Step 2: Export PathNode from __init__.py**

In `shared/lib_webbh/__init__.py`, add `PathNode` to the database imports block (after `MutationOutcome`):

```python
from lib_webbh.database import (
    Target,
    Asset,
    Identity,
    Location,
    Observation,
    CloudAsset,
    Parameter,
    Vulnerability,
    JobState,
    Alert,
    ApiSchema,
    MobileApp,
    AssetSnapshot,
    BountySubmission,
    ScheduledScan,
    ScopeViolation,
    CustomPlaybook,
    Campaign,
    EscalationContext,
    ChainFinding,
    VulnerabilityInsight,
    ToolHitRate,
    MutationOutcome,
    PathNode,
)
```

- [ ] **Step 3: Commit**

```bash
git add shared/lib_webbh/database.py shared/lib_webbh/__init__.py
git commit -m "feat(schema): add PathNode ORM model for directory hierarchy"
```

---

## Task 2: Add Alembic migration for path_nodes

**Files:**
- Create: `shared/lib_webbh/alembic/versions/002_add_path_nodes.py`

- [ ] **Step 1: Create migration file**

```python
# shared/lib_webbh/alembic/versions/002_add_path_nodes.py
"""Add path_nodes table for URL directory hierarchy.

Revision ID: 002_add_path_nodes
Revises: 001_m1_initial_restructure
"""

from alembic import op
import sqlalchemy as sa

revision = "002_add_path_nodes"
down_revision = "001_m1_initial_restructure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "path_nodes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer,
                  sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer,
                  sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("parent_id", sa.Integer,
                  sa.ForeignKey("path_nodes.id", ondelete="CASCADE"), nullable=True),
        sa.Column("path_segment", sa.Text, nullable=False),
        sa.Column("full_path", sa.Text, nullable=False),
        sa.Column("node_type", sa.String(50), nullable=True),
        sa.Column("source_tool", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  nullable=True, onupdate=sa.func.now()),
        sa.UniqueConstraint("target_id", "full_path", name="uq_path_nodes_target_path"),
    )
    op.create_index("idx_path_nodes_target", "path_nodes", ["target_id"])
    op.create_index("idx_path_nodes_parent", "path_nodes", ["parent_id"])
    op.create_index("idx_path_nodes_asset", "path_nodes", ["asset_id"])


def downgrade() -> None:
    op.drop_table("path_nodes")
```

- [ ] **Step 2: Apply migration against the running stack**

```bash
docker compose exec orchestrator alembic -c shared/lib_webbh/alembic/alembic.ini upgrade head
```

Expected output ends with: `Running upgrade 001_m1_initial_restructure -> 002_add_path_nodes, Add path_nodes table`

- [ ] **Step 3: Commit**

```bash
git add shared/lib_webbh/alembic/versions/002_add_path_nodes.py
git commit -m "feat(migration): add path_nodes table"
```

---

## Task 3: Implement PathTreeBuilder

**Files:**
- Create: `shared/lib_webbh/path_tree.py`
- Modify: `shared/lib_webbh/__init__.py`

- [ ] **Step 1: Write failing test first**

Create `tests/unit/test_path_tree.py`:

```python
# tests/unit/test_path_tree.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from lib_webbh.path_tree import PathTreeBuilder


class TestParseSegments:
    def test_simple_path(self):
        segments = PathTreeBuilder._parse_segments("https://example.com/admin/login")
        assert segments == [("/admin", "admin"), ("/admin/login", "login")]

    def test_root_only(self):
        segments = PathTreeBuilder._parse_segments("https://example.com/")
        assert segments == []

    def test_no_path(self):
        segments = PathTreeBuilder._parse_segments("https://example.com")
        assert segments == []

    def test_trailing_slash(self):
        segments = PathTreeBuilder._parse_segments("https://example.com/admin/")
        assert segments == [("/admin", "admin")]

    def test_deep_path(self):
        segments = PathTreeBuilder._parse_segments("https://t-mobile.com/accessory/jbl/item")
        assert segments == [
            ("/accessory", "accessory"),
            ("/accessory/jbl", "jbl"),
            ("/accessory/jbl/item", "item"),
        ]

    def test_invalid_url(self):
        segments = PathTreeBuilder._parse_segments("not-a-url")
        assert segments == []
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cd C:\Users\dat1k\Projects\WebAppBH && python -m pytest tests/unit/test_path_tree.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` — `path_tree` doesn't exist yet.

- [ ] **Step 3: Implement PathTreeBuilder**

Create `shared/lib_webbh/path_tree.py`:

```python
# shared/lib_webbh/path_tree.py
"""PathTreeBuilder — build and upsert a directory hierarchy from URL-valued assets."""

from __future__ import annotations

from urllib.parse import urlparse


class PathTreeBuilder:
    """Upsert path_nodes rows from a URL, building the full ancestor chain."""

    @staticmethod
    def _parse_segments(url: str) -> list[tuple[str, str]]:
        """Return list of (full_path, segment) tuples for each path component.

        E.g. "https://example.com/a/b/c" → [("/a","a"),("/a/b","b"),("/a/b/c","c")]
        Strips trailing slashes. Returns [] for URLs with no meaningful path.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return []

        path = parsed.path.rstrip("/")
        if not path or path == "/":
            return []

        parts = [p for p in path.split("/") if p]
        result = []
        for i, part in enumerate(parts):
            full = "/" + "/".join(parts[: i + 1])
            result.append((full, part))
        return result

    @classmethod
    async def upsert(
        cls,
        target_id: int,
        asset_id: int | None,
        url: str,
        node_type: str | None,
        source_tool: str | None,
    ) -> None:
        """Walk ``url``'s path and upsert one path_nodes row per segment.

        The leaf segment gets ``asset_id`` set. Intermediate nodes are created
        with ``asset_id=None`` and ``node_type="directory"`` if they don't
        already exist.

        Uses ON CONFLICT DO UPDATE so repeated calls from concurrent tools are safe.
        """
        from lib_webbh.database import PathNode, get_session
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        segments = cls._parse_segments(url)
        if not segments:
            return

        async with get_session() as session:
            parent_id: int | None = None

            for i, (full_path, segment) in enumerate(segments):
                is_leaf = i == len(segments) - 1
                this_asset_id = asset_id if is_leaf else None
                this_node_type = node_type if is_leaf else "directory"

                stmt = (
                    pg_insert(PathNode)
                    .values(
                        target_id=target_id,
                        asset_id=this_asset_id,
                        parent_id=parent_id,
                        path_segment=segment,
                        full_path=full_path,
                        node_type=this_node_type,
                        source_tool=source_tool,
                    )
                    .on_conflict_do_update(
                        index_elements=["target_id", "full_path"],
                        set_={
                            "asset_id": pg_insert(PathNode).excluded.asset_id,
                            "node_type": pg_insert(PathNode).excluded.node_type,
                            "source_tool": pg_insert(PathNode).excluded.source_tool,
                        },
                    )
                    .returning(PathNode.id)
                )
                result = await session.execute(stmt)
                row = result.fetchone()
                parent_id = row[0] if row else None

            await session.commit()
```

- [ ] **Step 4: Export PathTreeBuilder from __init__.py**

Add after the PathNode export line in `shared/lib_webbh/__init__.py`:

```python
from lib_webbh.path_tree import PathTreeBuilder
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
python -m pytest tests/unit/test_path_tree.py -v
```

Expected: `5 passed`

- [ ] **Step 6: Commit**

```bash
git add shared/lib_webbh/path_tree.py shared/lib_webbh/__init__.py tests/unit/test_path_tree.py
git commit -m "feat(lib): add PathTreeBuilder for URL directory hierarchy"
```

---

## Task 4: Add path_nodes API endpoints + fix asset pagination

**Files:**
- Modify: `orchestrator/main.py`
- Modify: `dashboard/src/lib/api.ts`

- [ ] **Step 1: Add two endpoints to orchestrator/main.py**

Find the line `# GET /api/v1/assets — list assets for a target` (~line 1231) and add these two endpoints immediately before it:

```python
# ---------------------------------------------------------------------------
# GET /api/v1/path_nodes — tree for a target (optionally scoped to asset)
# ---------------------------------------------------------------------------
@app.get("/api/v1/path_nodes")
async def list_path_nodes(
    target_id: int = Query(...),
    asset_id: Optional[int] = Query(None),
):
    from lib_webbh.database import PathNode
    async with get_session() as session:
        stmt = select(PathNode).where(PathNode.target_id == target_id).order_by(PathNode.full_path)
        result = await session.execute(stmt)
        nodes = result.scalars().all()

    node_map: dict[int, dict] = {}
    for n in nodes:
        node_map[n.id] = {
            "id": n.id,
            "parent_id": n.parent_id,
            "asset_id": n.asset_id,
            "path_segment": n.path_segment,
            "full_path": n.full_path,
            "node_type": n.node_type,
            "source_tool": n.source_tool,
            "children": [],
        }

    roots: list[dict] = []
    for node in node_map.values():
        pid = node["parent_id"]
        if pid is None or pid not in node_map:
            roots.append(node)
        else:
            node_map[pid]["children"].append(node)

    return {"nodes": roots}


# ---------------------------------------------------------------------------
# GET /api/v1/path_nodes/{node_id} — single node with linked asset detail
# ---------------------------------------------------------------------------
@app.get("/api/v1/path_nodes/{node_id}")
async def get_path_node(node_id: int):
    from lib_webbh.database import PathNode, Asset as AssetModel, Vulnerability as VulnModel
    async with get_session() as session:
        node = await session.get(PathNode, node_id)
        if node is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Node not found")

        asset_detail = None
        if node.asset_id:
            asset = await session.get(AssetModel, node.asset_id)
            if asset:
                vuln_result = await session.execute(
                    select(func.count(), func.min(VulnModel.severity))
                    .where(VulnModel.asset_id == node.asset_id)
                )
                vuln_row = vuln_result.one()
                asset_detail = {
                    "id": asset.id,
                    "asset_type": asset.asset_type,
                    "asset_value": asset.asset_value,
                    "scope_classification": asset.scope_classification,
                    "source_tool": asset.source_tool,
                    "created_at": asset.created_at.isoformat() if asset.created_at else None,
                    "vuln_count": vuln_row[0] or 0,
                    "tech": asset.tech,
                }

    return {
        "id": node.id,
        "path_segment": node.path_segment,
        "full_path": node.full_path,
        "node_type": node.node_type,
        "source_tool": node.source_tool,
        "asset": asset_detail,
    }
```

- [ ] **Step 2: Add getAllAssets and path_nodes calls to api.ts**

In `dashboard/src/lib/api.ts`, replace the existing `getAssets` function and add new ones:

```typescript
  async getAllAssets(
    targetId: number,
    onProgress?: (loaded: number, total: number) => void,
  ): Promise<AssetWithLocations[]> {
    const PAGE_SIZE = 500;
    const first = await request<AssetsResponse>(
      `/api/v1/assets?target_id=${targetId}&page=1&page_size=${PAGE_SIZE}`,
    );
    const all: AssetWithLocations[] = [...first.assets];
    onProgress?.(all.length, first.total);

    const totalPages = Math.ceil(first.total / PAGE_SIZE);
    for (let page = 2; page <= totalPages; page++) {
      const res = await request<AssetsResponse>(
        `/api/v1/assets?target_id=${targetId}&page=${page}&page_size=${PAGE_SIZE}`,
      );
      all.push(...res.assets);
      onProgress?.(all.length, first.total);
    }
    return all;
  },

  getPathNodes(targetId: number) {
    return request<{ nodes: PathNodeTree[] }>(`/api/v1/path_nodes?target_id=${targetId}`);
  },

  getPathNode(nodeId: number) {
    return request<PathNodeDetail>(`/api/v1/path_nodes/${nodeId}`);
  },
  // Note: getAssetLocations(assetId) already exists in api.ts — do not re-declare it.
```

Also add the new TypeScript interfaces near the top of api.ts (after `AssetsResponse`):

```typescript
export interface PathNodeTree {
  id: number;
  parent_id: number | null;
  asset_id: number | null;
  path_segment: string;
  full_path: string;
  node_type: string | null;
  source_tool: string | null;
  children: PathNodeTree[];
}

export interface PathNodeDetail {
  id: number;
  path_segment: string;
  full_path: string;
  node_type: string | null;
  source_tool: string | null;
  asset: {
    id: number;
    asset_type: string;
    asset_value: string;
    scope_classification: string;
    source_tool: string | null;
    created_at: string | null;
    vuln_count: number;
    tech: Record<string, unknown> | null;
  } | null;
}
```

- [ ] **Step 3: Commit**

```bash
git add orchestrator/main.py dashboard/src/lib/api.ts
git commit -m "feat(api): add path_nodes endpoints and getAllAssets pagination"
```

---

## Task 5: C2 page cleanup

**Files:**
- Modify: `dashboard/src/app/campaign/c2/page.tsx`

- [ ] **Step 1: Remove imports at the top of c2/page.tsx**

Remove these import lines:

```typescript
import AssetTree, { type TreeNode } from "@/components/c2/AssetTree";
import AssetDetailDrawer from "@/components/c2/AssetDetailDrawer";
import QueueHealthWidget from "@/components/c2/QueueHealthWidget";
```

- [ ] **Step 2: Remove state declarations (lines ~126–136)**

Remove these state declarations:

```typescript
const [treeRoots, setTreeRoots] = useState<TreeNode[]>([]);
const [selectedAsset, setSelectedAsset] =
  useState<AssetWithLocations | null>(null);
const [allAssets, setAllAssets] = useState<AssetWithLocations[]>([]);
```

Also remove `lastMergedIdx` ref:

```typescript
const lastMergedIdx = useRef(0);
```

- [ ] **Step 3: Remove buildTree function (lines ~26–65)**

Remove the entire `buildTree` function at the top of the file.

- [ ] **Step 4: Remove the asset-loading useEffect (~lines 221–231)**

Remove:

```typescript
  useEffect(() => {
    if (!activeTarget) return;
    lastMergedIdx.current = 0;
    api
      .getAssets(activeTarget.id)
      .then((res) => {
        setAllAssets(res.assets);
        setTreeRoots(buildTree(activeTarget.base_domain, res.assets));
      })
      .catch(() => {});
  }, [activeTarget]);
```

- [ ] **Step 5: In the SSE merge useEffect, remove only the NEW_ASSET branch**

Find the SSE merge `useEffect`. Remove just the `NEW_ASSET` handling block while keeping the `KILL_ALL`, `RERUN_STARTED`, and `CLEAN_SLATE` blocks. The block to remove is:

```typescript
    const assetEvents = newEvents.filter((e) => e.event === "NEW_ASSET");
    if (assetEvents.length > 0) {
      setTreeRoots((prev) => {
        if (prev.length === 0) return prev;
        const root = {
          ...prev[0],
          children: [...(prev[0].children ?? [])],
        };
        for (const evt of assetEvents) {
          const d = evt as Record<string, unknown>;
          root.children!.push({
            id: `sse-${String(d.asset_value)}-${Date.now()}`,
            label: String(d.asset_value ?? ""),
            type: (String(d.asset_type ?? "subdomain") === "ip"
              ? "ip"
              : "subdomain") as TreeNode["type"],
          });
        }
        return [root];
      });
    }
```

- [ ] **Step 6: Remove handleAssetSelect callback**

Remove:

```typescript
  const handleAssetSelect = useCallback(
    (nodeId: string) => {
      const assetIdStr = nodeId.replace("asset-", "");
      const assetId = parseInt(assetIdStr, 10);
      if (isNaN(assetId)) return;
      const found = allAssets.find((a) => a.id === assetId);
      if (found) setSelectedAsset(found);
    },
    [allAssets],
  );
```

- [ ] **Step 7: Replace the Asset Tree + Campaign Timeline grid with full-width Timeline**

Find the JSX block (around line 463):

```tsx
      {/* Asset Tree (1/3) + Campaign Timeline (2/3) */}
      <div className="grid grid-cols-3 gap-5">
        <div className="col-span-1" data-testid="c2-asset-tree">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="section-label mb-3">ASSET TREE</div>
            <div className="max-h-[600px] overflow-y-auto">
              <AssetTree
                roots={treeRoots}
                onSelect={handleAssetSelect}
              />
            </div>
          </div>
        </div>
        <div className="col-span-2">
          <div data-testid="c2-timeline" className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="section-label mb-3">CAMPAIGN TIMELINE</div>
            <CampaignTimeline jobs={jobs} />
          </div>
        </div>
      </div>
```

Replace with:

```tsx
      {/* Campaign Timeline — full width */}
      <div data-testid="c2-timeline" className="rounded-lg border border-border bg-bg-secondary p-4">
        <div className="section-label mb-3">CAMPAIGN TIMELINE</div>
        <CampaignTimeline jobs={jobs} />
      </div>
```

- [ ] **Step 8: Remove QueueHealthWidget from the System Pulse row**

Find:

```tsx
      {/* System Pulse + Queue Health */}
      <div className="grid grid-cols-2 gap-5">
        <SystemPulse />
        <QueueHealthWidget />
      </div>
```

Replace with:

```tsx
      {/* System Pulse */}
      <SystemPulse />
```

- [ ] **Step 9: Remove AssetDetailDrawer JSX**

Remove:

```tsx
      {/* Asset Detail Drawer */}
      <AssetDetailDrawer
        asset={selectedAsset}
        onClose={() => setSelectedAsset(null)}
      />
```

- [ ] **Step 10: Verify TypeScript compiles**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 11: Commit**

```bash
git add dashboard/src/app/campaign/c2/page.tsx
git commit -m "refactor(c2): remove AssetTree, QueueHealthWidget, promote Timeline to full width"
```

---

## Task 6: Assets table — pagination fix and row navigation

**Files:**
- Modify: `dashboard/src/app/campaign/assets/page.tsx`

- [ ] **Step 1: Replace fetchData with getAllAssets and add progress state**

Replace the state declarations and `fetchData` callback at the top of `AssetsPage`:

```typescript
  const [data, setData] = useState<AssetWithLocations[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadedCount, setLoadedCount] = useState(0);
  const [totalCount, setTotalCount] = useState(0);
  const [error, setError] = useState(false);
```

Replace the `fetchData` callback:

```typescript
  const fetchData = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError(false);
    setLoadedCount(0);
    setTotalCount(0);
    try {
      const assets = await api.getAllAssets(activeTarget.id, (loaded, total) => {
        setLoadedCount(loaded);
        setTotalCount(total);
      });
      setData(assets);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);
```

- [ ] **Step 2: Update loading state render to show progress**

Find the loading state JSX block and replace:

```tsx
  if (loading) {
    return (
      <div className="space-y-5 animate-fade-in">
        <PageHeader count={0} />
        <div className="flex h-64 items-center justify-center gap-3">
          <Loader2 className="h-6 w-6 animate-spin text-neon-orange" />
          {totalCount > 0 && (
            <span className="text-sm text-text-muted font-mono">
              Loading {loadedCount} / {totalCount}…
            </span>
          )}
        </div>
      </div>
    );
  }
```

- [ ] **Step 3: Add router import and useRouter usage (already present — verify)**

Confirm `useRouter` is imported from `"next/navigation"` and `router` is initialised. It already is in the existing code.

- [ ] **Step 4: Remove expand-related state and handlers**

Remove these state declarations:

```typescript
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<DetailTab>("locations");
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailData, setDetailData] = useState<DetailData | null>(null);
```

Remove `DetailData` interface, `DetailTab` type, and the `handleExpand` callback.

- [ ] **Step 5: Replace AssetRowGroup with a plain clickable row**

Replace the `paged.map((row) => ...)` block in the table body:

```tsx
              paged.map((row) => {
                const ports = formatPorts(row.locations);
                const vc = vulnCounts[row.id];
                const vulnCount = vc?.count ?? 0;
                const highSev = vc?.severity ?? "info";
                const scopeClass = row.scope_classification ?? "pending";

                return (
                  <tr
                    key={row.id}
                    data-testid={`asset-row-${row.id}`}
                    onClick={() => router.push(`/campaign/assets/${row.id}`)}
                    className={`cursor-pointer bg-bg-secondary transition-colors hover:bg-bg-tertiary ${
                      isSelected(row.id) ? "ring-1 ring-inset ring-neon-blue/30" : ""
                    }`}
                  >
                    <td className="px-2 py-2.5">
                      <button
                        data-testid={`asset-checkbox-${row.id}`}
                        onClick={(e) => { e.stopPropagation(); toggleSelect(row.id); }}
                        className="rounded p-0.5 hover:bg-bg-surface transition-colors"
                      >
                        {selected.has(row.id) ? (
                          <CheckSquare className="h-4 w-4 text-neon-blue" />
                        ) : (
                          <Square className="h-4 w-4 text-text-muted" />
                        )}
                      </button>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
                        TYPE_BADGE[row.asset_type] ?? TYPE_BADGE.url
                      }`}>
                        {row.asset_type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-text-primary">{row.asset_value}</td>
                    <td className="px-4 py-2.5">
                      <span data-testid={`asset-scope-badge-${row.id}`}
                        className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
                          CLASSIFICATION_BADGE[scopeClass] ?? CLASSIFICATION_BADGE.undetermined
                        }`}>
                        {scopeClass.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">{ports.display}</td>
                    <td className="px-4 py-2.5">
                      <span data-testid={`asset-vuln-badge-${row.id}`}
                        className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
                          vulnCount > 0 ? SEVERITY_COLORS[highSev] ?? SEVERITY_COLORS.info
                            : "text-text-muted bg-bg-surface border-border"
                        }`}>
                        {vulnCount}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
                      {row.source_tool ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
                      {relativeTime(row.created_at)}
                    </td>
                  </tr>
                );
              })
```

Also update the `isSelected` helper — add this alias near the top of the component:

```typescript
  const isSelected = (id: number) => selected.has(id);
```

- [ ] **Step 6: Update the table header — remove expand chevron column**

Remove the `<th className="w-10 px-2 py-3" />` blank column (the expand chevron placeholder). The table now has 8 columns: checkbox + Type + Hostname/IP + Scope + Ports + Vulns + Source Tool + Discovered.

Also update `colSpan={9}` to `colSpan={8}` in the empty-filter row.

- [ ] **Step 7: Remove unused components**

Delete the `AssetRowGroup`, `TabButton`, `LocationsTab`, `VulnerabilitiesTab`, `CloudTab`, `TreeTab`, and `ChainNode` definitions from the bottom of the file — they're no longer needed.

- [ ] **Step 8: Remove vulnCounts state (now loaded lazily from detail page)**

Remove:

```typescript
  const [vulnCounts, setVulnCounts] = useState<Record<number, { count: number; severity: string }>>({});
```

The vuln badge column can be omitted from the table or left showing `—` until the detail page loads it. To keep the table lean, remove the Vulns column from the table header and row for now (it loads on the detail page).

- [ ] **Step 9: Verify TypeScript compiles**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 10: Commit**

```bash
git add dashboard/src/app/campaign/assets/page.tsx
git commit -m "feat(assets): fix pagination cap, add row navigation to detail page"
```

---

## Task 7: Asset detail page components

**Files:**
- Create: `dashboard/src/components/assets/DirectoryTree.tsx`
- Create: `dashboard/src/components/assets/PortsList.tsx`
- Create: `dashboard/src/components/assets/AssetNodeDrawer.tsx`

- [ ] **Step 1: Create DirectoryTree component**

```tsx
// dashboard/src/components/assets/DirectoryTree.tsx
"use client";

import { useState } from "react";
import { ChevronRight, ChevronDown, Folder, File, Globe } from "lucide-react";
import type { PathNodeTree } from "@/lib/api";

const NODE_TYPE_ICON: Record<string, React.ReactNode> = {
  directory: <Folder className="h-3.5 w-3.5 text-neon-orange" />,
  file: <File className="h-3.5 w-3.5 text-text-secondary" />,
  sensitive_file: <File className="h-3.5 w-3.5 text-danger" />,
  form: <Globe className="h-3.5 w-3.5 text-neon-blue" />,
  url: <Globe className="h-3.5 w-3.5 text-text-muted" />,
};

const NODE_TYPE_BADGE: Record<string, string> = {
  directory: "bg-neon-orange/10 text-neon-orange border-neon-orange/20",
  file: "bg-bg-surface text-text-secondary border-border",
  sensitive_file: "bg-danger/10 text-danger border-danger/20",
  form: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  url: "bg-bg-surface text-text-muted border-border",
};

function TreeNodeRow({
  node,
  selectedId,
  onSelect,
  depth,
}: {
  node: PathNodeTree;
  selectedId: number | null;
  onSelect: (id: number) => void;
  depth: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = node.children.length > 0;
  const isSelected = node.id === selectedId;
  const icon = NODE_TYPE_ICON[node.node_type ?? "url"] ?? NODE_TYPE_ICON.url;
  const badge = NODE_TYPE_BADGE[node.node_type ?? "url"] ?? NODE_TYPE_BADGE.url;

  return (
    <div>
      <div
        data-testid={`tree-node-${node.id}`}
        className={`flex cursor-pointer items-center gap-1.5 rounded px-2 py-1 text-sm transition-colors ${
          isSelected
            ? "bg-neon-orange/10 text-neon-orange"
            : "hover:bg-bg-tertiary text-text-primary"
        }`}
        style={{ paddingLeft: `${0.5 + depth * 1.25}rem` }}
        onClick={() => onSelect(node.id)}
      >
        <button
          onClick={(e) => { e.stopPropagation(); if (hasChildren) setOpen((o) => !o); }}
          className="flex-shrink-0"
        >
          {hasChildren ? (
            open ? <ChevronDown className="h-3.5 w-3.5 text-text-muted" />
                 : <ChevronRight className="h-3.5 w-3.5 text-text-muted" />
          ) : (
            <span className="inline-block w-3.5" />
          )}
        </button>
        {icon}
        <span className="font-mono truncate">{node.path_segment}</span>
        {node.node_type && (
          <span className={`ml-auto flex-shrink-0 rounded border px-1.5 py-0 text-[10px] font-medium ${badge}`}>
            {node.node_type}
          </span>
        )}
      </div>
      {open && hasChildren && (
        <div>
          {node.children.map((child) => (
            <TreeNodeRow
              key={child.id}
              node={child}
              selectedId={selectedId}
              onSelect={onSelect}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function DirectoryTree({
  nodes,
  selectedId,
  onSelect,
}: {
  nodes: PathNodeTree[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}) {
  if (nodes.length === 0) {
    return (
      <p className="py-8 text-center text-xs text-text-muted">
        No path hierarchy found. Run a scan to populate the directory tree.
      </p>
    );
  }

  return (
    <div className="font-mono text-sm">
      {nodes.map((node) => (
        <TreeNodeRow
          key={node.id}
          node={node}
          selectedId={selectedId}
          onSelect={onSelect}
          depth={0}
        />
      ))}
    </div>
  );
}
```

- [ ] **Step 2: Create PortsList component**

```tsx
// dashboard/src/components/assets/PortsList.tsx
"use client";

import type { Location } from "@/types/schema";

const STATE_BADGE: Record<string, string> = {
  open: "bg-neon-green-glow text-neon-green border-neon-green/20",
  closed: "bg-bg-surface text-text-muted border-border",
  filtered: "bg-sev-medium/10 text-sev-medium border-sev-medium/20",
};

export default function PortsList({
  locations,
  selectedId,
  onSelect,
}: {
  locations: Location[];
  selectedId: number | null;
  onSelect: (loc: Location) => void;
}) {
  if (locations.length === 0) {
    return (
      <p className="py-4 text-center text-xs text-text-muted">No ports found.</p>
    );
  }

  return (
    <div className="space-y-1">
      {locations.map((loc) => (
        <button
          key={loc.id}
          data-testid={`port-row-${loc.id}`}
          onClick={() => onSelect(loc)}
          className={`w-full rounded px-3 py-2 text-left text-xs transition-colors ${
            selectedId === loc.id
              ? "bg-neon-orange/10 text-neon-orange"
              : "hover:bg-bg-tertiary text-text-primary"
          }`}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono font-medium">:{loc.port}</span>
            <span className={`rounded border px-1.5 py-0 text-[10px] font-medium ${
              STATE_BADGE[loc.state ?? ""] ?? STATE_BADGE.closed
            }`}>
              {loc.state ?? "—"}
            </span>
          </div>
          {loc.service && (
            <div className="mt-0.5 font-mono text-[10px] text-text-muted">{loc.service}</div>
          )}
          {loc.protocol && (
            <div className="font-mono text-[10px] text-text-muted">{loc.protocol}</div>
          )}
        </button>
      ))}
    </div>
  );
}
```

- [ ] **Step 3: Create AssetNodeDrawer component**

```tsx
// dashboard/src/components/assets/AssetNodeDrawer.tsx
"use client";

import { X, Shield, Clock, Wrench, Tag, Network } from "lucide-react";
import type { PathNodeDetail } from "@/lib/api";
import type { Location } from "@/types/schema";

const SCOPE_BADGE: Record<string, string> = {
  in_scope: "bg-neon-green-glow text-neon-green border-neon-green/20",
  out_of_scope: "bg-danger/10 text-danger border-danger/20",
  pending: "bg-sev-medium/10 text-sev-medium border-sev-medium/20",
  associated: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  undetermined: "bg-bg-surface text-text-muted border-border",
};

const TYPE_BADGE: Record<string, string> = {
  directory: "bg-neon-orange/10 text-neon-orange border-neon-orange/20",
  file: "bg-bg-surface text-text-secondary border-border",
  sensitive_file: "bg-danger/10 text-danger border-danger/20",
  form: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  url: "bg-bg-surface text-text-muted border-border",
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-danger",
  high: "text-neon-orange",
  medium: "text-sev-medium",
  low: "text-neon-blue",
  info: "text-text-muted",
};

function Row({ icon, label, value }: { icon: React.ReactNode; label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 py-1.5 border-b border-border last:border-0">
      <span className="mt-0.5 text-text-muted flex-shrink-0">{icon}</span>
      <span className="text-xs text-text-muted w-20 flex-shrink-0">{label}</span>
      <span className="text-xs text-text-primary break-all">{value}</span>
    </div>
  );
}

export type DrawerState =
  | { type: "node"; detail: PathNodeDetail }
  | { type: "port"; location: Location };

export default function AssetNodeDrawer({
  state,
  onClose,
}: {
  state: DrawerState | null;
  onClose: () => void;
}) {
  if (!state) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      {/* Drawer */}
      <div className="fixed right-0 top-0 z-50 h-full w-80 border-l border-border bg-bg-secondary shadow-2xl overflow-y-auto">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <span className="text-sm font-semibold text-text-primary">
            {state.type === "node" ? state.detail.path_segment : `:${state.location.port}`}
          </span>
          <button
            onClick={onClose}
            className="rounded p-1 hover:bg-bg-tertiary transition-colors"
          >
            <X className="h-4 w-4 text-text-muted" />
          </button>
        </div>

        <div className="px-4 py-3">
          {state.type === "port" ? (
            <div className="space-y-1">
              <Row icon={<Network className="h-3.5 w-3.5" />} label="Port" value={
                <span className="font-mono">{state.location.port}</span>
              } />
              <Row icon={<Network className="h-3.5 w-3.5" />} label="Protocol" value={state.location.protocol ?? "—"} />
              <Row icon={<Wrench className="h-3.5 w-3.5" />} label="Service" value={
                <span className="font-mono">{state.location.service ?? "—"}</span>
              } />
              <Row icon={<Shield className="h-3.5 w-3.5" />} label="State" value={state.location.state ?? "—"} />
            </div>
          ) : (
            <div className="space-y-1">
              {state.detail.node_type && (
                <Row icon={<Tag className="h-3.5 w-3.5" />} label="Type" value={
                  <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                    TYPE_BADGE[state.detail.node_type] ?? TYPE_BADGE.url
                  }`}>
                    {state.detail.node_type}
                  </span>
                } />
              )}
              {state.detail.asset && (
                <>
                  <Row icon={<Shield className="h-3.5 w-3.5" />} label="Scope" value={
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                      SCOPE_BADGE[state.detail.asset.scope_classification] ?? SCOPE_BADGE.undetermined
                    }`}>
                      {state.detail.asset.scope_classification.replace(/_/g, " ")}
                    </span>
                  } />
                  <Row icon={<Wrench className="h-3.5 w-3.5" />} label="Source" value={
                    <span className="font-mono">{state.detail.asset.source_tool ?? "—"}</span>
                  } />
                  <Row icon={<Clock className="h-3.5 w-3.5" />} label="Found" value={
                    state.detail.asset.created_at
                      ? new Date(state.detail.asset.created_at).toLocaleString()
                      : "—"
                  } />
                  {state.detail.asset.vuln_count > 0 && (
                    <Row icon={<Shield className="h-3.5 w-3.5" />} label="Vulns" value={
                      <span className={`font-semibold ${SEV_COLORS.high}`}>
                        {state.detail.asset.vuln_count}
                      </span>
                    } />
                  )}
                  {state.detail.asset.tech && Object.keys(state.detail.asset.tech).length > 0 && (
                    <div className="mt-3">
                      <p className="mb-1 text-[10px] font-medium uppercase tracking-wider text-text-muted">
                        Tech Stack
                      </p>
                      <pre className="rounded bg-bg-tertiary p-2 text-[10px] text-text-secondary overflow-x-auto">
                        {JSON.stringify(state.detail.asset.tech, null, 2)}
                      </pre>
                    </div>
                  )}
                </>
              )}
              <Row icon={<Wrench className="h-3.5 w-3.5" />} label="Path" value={
                <span className="font-mono text-[10px]">{state.detail.full_path}</span>
              } />
            </div>
          )}
        </div>
      </div>
    </>
  );
}
```

- [ ] **Step 4: Verify TypeScript compiles**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/components/assets/
git commit -m "feat(assets): add DirectoryTree, PortsList, AssetNodeDrawer components"
```

---

## Task 8: Asset detail page layout

**Files:**
- Create: `dashboard/src/app/campaign/assets/[id]/page.tsx`

- [ ] **Step 1: Create the detail page**

```tsx
// dashboard/src/app/campaign/assets/[id]/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { ChevronLeft, Loader2, AlertTriangle } from "lucide-react";
import { api, type PathNodeTree, type PathNodeDetail } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import DirectoryTree from "@/components/assets/DirectoryTree";
import PortsList from "@/components/assets/PortsList";
import AssetNodeDrawer, { type DrawerState } from "@/components/assets/AssetNodeDrawer";
import type { Location, AssetWithLocations } from "@/types/schema";

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  const assetId = parseInt(params.id, 10);

  const [asset, setAsset] = useState<AssetWithLocations | null>(null);
  const [treeNodes, setTreeNodes] = useState<PathNodeTree[]>([]);
  const [locations, setLocations] = useState<Location[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  const [selectedPortId, setSelectedPortId] = useState<number | null>(null);
  const [drawerState, setDrawerState] = useState<DrawerState | null>(null);
  const [drawerLoading, setDrawerLoading] = useState(false);

  useEffect(() => {
    if (!activeTarget || isNaN(assetId)) return;

    setLoading(true);
    setError(false);

    Promise.all([
      api.getAllAssets(activeTarget.id),
      api.getPathNodes(activeTarget.id),
      api.getAssetLocations(assetId),
    ])
      .then(([assets, treeRes, locsRes]) => {
        const found = assets.find((a) => a.id === assetId) ?? null;
        setAsset(found);
        setTreeNodes(treeRes.nodes);
        setLocations(locsRes.locations);
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, [activeTarget, assetId]);

  const handleNodeSelect = useCallback(async (nodeId: number) => {
    setSelectedNodeId(nodeId);
    setSelectedPortId(null);
    setDrawerLoading(true);
    try {
      const detail = await api.getPathNode(nodeId);
      setDrawerState({ type: "node", detail });
    } catch {
      setDrawerState(null);
    } finally {
      setDrawerLoading(false);
    }
  }, []);

  const handlePortSelect = useCallback((loc: Location) => {
    setSelectedPortId(loc.id);
    setSelectedNodeId(null);
    setDrawerState({ type: "port", location: loc });
  }, []);

  const closeDrawer = useCallback(() => {
    setDrawerState(null);
    setSelectedNodeId(null);
    setSelectedPortId(null);
  }, []);

  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">No active campaign selected.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-5">
        <BackLink />
        <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-danger/30 bg-danger/5 py-16">
          <AlertTriangle className="h-10 w-10 text-danger" />
          <p className="text-text-primary font-medium">Failed to load asset.</p>
          <button
            onClick={() => router.back()}
            className="rounded-md border border-border bg-bg-surface px-4 py-2 text-sm text-text-primary hover:bg-bg-tertiary transition-colors"
          >
            Go back
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="space-y-5">
        <BackLink />
        <div className="flex h-64 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-neon-orange" />
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col gap-4 animate-fade-in">
      {/* Header */}
      <div className="flex-shrink-0">
        <BackLink />
        <h1 className="mt-2 font-mono text-lg text-text-primary break-all">
          {asset?.asset_value ?? `Asset #${assetId}`}
        </h1>
      </div>

      {/* Two-column body */}
      <div className="flex min-h-0 flex-1 gap-4">
        {/* Directory Tree */}
        <div className="flex-1 overflow-y-auto rounded-lg border border-border bg-bg-secondary p-4">
          <div className="section-label mb-3">DIRECTORY TREE</div>
          <DirectoryTree
            nodes={treeNodes}
            selectedId={selectedNodeId}
            onSelect={handleNodeSelect}
          />
        </div>

        {/* Ports */}
        <div className="w-56 flex-shrink-0 overflow-y-auto rounded-lg border border-border bg-bg-secondary p-4">
          <div className="section-label mb-3">PORTS</div>
          {drawerLoading && (
            <div className="flex justify-center py-2">
              <Loader2 className="h-4 w-4 animate-spin text-neon-orange" />
            </div>
          )}
          <PortsList
            locations={locations}
            selectedId={selectedPortId}
            onSelect={handlePortSelect}
          />
        </div>
      </div>

      {/* Side drawer */}
      <AssetNodeDrawer state={drawerState} onClose={closeDrawer} />
    </div>
  );
}

function BackLink() {
  const router = useRouter();
  return (
    <button
      onClick={() => router.push("/campaign/assets")}
      className="flex items-center gap-1 text-sm text-text-muted hover:text-text-primary transition-colors"
    >
      <ChevronLeft className="h-4 w-4" />
      Assets
    </button>
  );
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/app/campaign/assets/[id]/page.tsx
git commit -m "feat(assets): add full-page asset detail view with directory tree and ports panel"
```

---

## Task 9: Wire PathTreeBuilder into save_asset

**Files:**
- Modify: `workers/info_gathering/base_tool.py`

- [ ] **Step 1: Import PathTreeBuilder at the top of base_tool.py**

After the existing `from lib_webbh import (...)` block, add:

```python
from lib_webbh.path_tree import PathTreeBuilder
```

- [ ] **Step 2: Call PathTreeBuilder.upsert inside save_asset after the asset is created**

Find the line `return asset.id` inside `save_asset` (around line 120). Insert the PathTreeBuilder call before the return:

```python
            await session.commit()
            await session.refresh(asset)

            # Populate path hierarchy for URL-valued assets
            if asset_value.startswith(("http://", "https://")):
                try:
                    await PathTreeBuilder.upsert(
                        target_id=target_id,
                        asset_id=asset.id,
                        url=asset_value,
                        node_type=asset_type,
                        source_tool=source_tool,
                    )
                except Exception as exc:
                    logger.warning(
                        "PathTreeBuilder.upsert failed",
                        asset_value=asset_value,
                        error=str(exc),
                    )

            return asset.id
```

- [ ] **Step 3: Commit**

```bash
git add workers/info_gathering/base_tool.py
git commit -m "feat(worker): wire PathTreeBuilder into save_asset for URL assets"
```

---

## Task 10: Dockerfile — install missing binaries + add resolvers.txt

**Files:**
- Modify: `docker/Dockerfile.info_gathering`
- Create: `workers/info_gathering/resolvers.txt`

- [ ] **Step 1: Add missing binaries to Dockerfile.info_gathering**

Find the block of `go install` lines and add after the existing ones:

```dockerfile
# Subdomain enumeration
RUN go install -v github.com/owasp-amass/amass/v4/...@latest

# Technology detection
RUN go install github.com/rverton/webanalyze/cmd/webanalyze@latest

# Content discovery
RUN go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest
```

For `wappalyzer` — the CLI binary does not have a stable maintained version. Replace the `wappalyzer` CLI call in `tools/wappalyzer.py` with the `python-Wappalyzer` library instead (see Task 11).

Add to the Python pip block:

```dockerfile
RUN pip install --no-cache-dir python-Wappalyzer || true
```

The full updated Dockerfile should have these sections:

```dockerfile
# Go tools installed via go install
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/hakluke/hakrawler@latest
RUN go install -v github.com/owasp-amass/amass/v4/...@latest
RUN go install github.com/rverton/webanalyze/cmd/webanalyze@latest
RUN go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest

# Python tools
RUN pip install --no-cache-dir paramspider || true
RUN pip install --no-cache-dir wafw00f==2.2.0
RUN pip install --no-cache-dir python-Wappalyzer || true
```

- [ ] **Step 2: Create resolvers.txt for massdns**

Create `workers/info_gathering/resolvers.txt` with reliable public DNS resolvers:

```
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
```

The massdns command references `/app/workers/info_gathering/resolvers.txt` — this file is copied into the container by the `COPY workers/info_gathering/ /app/workers/info_gathering/` Dockerfile line.

- [ ] **Step 3: Commit**

```bash
git add docker/Dockerfile.info_gathering workers/info_gathering/resolvers.txt
git commit -m "fix(docker): install amass, webanalyze, ffuf; add python-Wappalyzer; add massdns resolvers"
```

---

## Task 11: Fix wrong method signatures in naabu + vhost_prober + wappalyzer

**Files:**
- Modify: `workers/info_gathering/tools/naabu.py`
- Modify: `workers/info_gathering/tools/vhost_prober.py`
- Modify: `workers/info_gathering/tools/wappalyzer.py`

- [ ] **Step 1: Fix naabu.py — use save_location instead of save_observation**

`naabu` discovers open ports and should save them as `Location` rows linked to the target's base-domain asset. Replace the entire `execute` method:

```python
    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        asset_id = kwargs.get("asset_id")
        if not target or not asset_id:
            return

        cmd = ["naabu", "-host", target.base_domain, "-json", "-silent"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=600)
        except Exception as exc:
            logger.error(
                "naabu failed",
                target=target.base_domain,
                error=str(exc),
            )
            return

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                port = data.get("port")
                if port:
                    await self.save_location(
                        asset_id=asset_id,
                        port=int(port),
                        protocol="tcp",
                        state="open",
                    )
            except (json.JSONDecodeError, ValueError):
                continue
```

- [ ] **Step 2: Fix vhost_prober.py — use save_observation with correct asset_id**

`vhost_prober` should save observations linked to the subdomain's asset_id, not target_id. The tool needs to resolve the asset_id for each subdomain. Replace the inner save call:

```python
    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        from lib_webbh.database import Asset
        from lib_webbh import get_session
        from sqlalchemy import select

        async with get_session() as session:
            stmt = select(Asset.id, Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type == "subdomain",
            )
            result = await session.execute(stmt)
            subdomains = [(row[0], row[1]) for row in result.all()]

        if len(subdomains) < 2:
            return

        base_url = f"https://{target.base_domain}"
        for sub_asset_id, subdomain in subdomains:
            try:
                async with aiohttp.ClientSession() as http_session:
                    headers = {"Host": subdomain}
                    async with http_session.get(
                        base_url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302, 403):
                            await self.save_observation(
                                asset_id=sub_asset_id,
                                tech_stack={"vhost": subdomain, "status": resp.status},
                            )
            except Exception:
                continue
```

- [ ] **Step 3: Fix wappalyzer.py — use python-Wappalyzer library instead of CLI**

Replace the entire `wappalyzer.py` implementation:

```python
# workers/info_gathering/tools/wappalyzer.py
"""Wappalyzer wrapper — technology detection (WSTG 4.1.8)."""
from __future__ import annotations

from typing import Any

from workers.info_gathering.base_tool import InfoGatheringTool, logger
from workers.info_gathering.fingerprint_aggregator import ProbeResult

_TECH_SLOTS: dict[str, str] = {
    "Laravel": "framework", "Django": "framework", "Ruby on Rails": "framework",
    "Express": "framework", "ASP.NET MVC": "framework", "Spring Boot": "framework",
    "Spring Framework": "framework", "Flask": "framework", "Symfony": "framework",
    "CodeIgniter": "framework", "Nuxt.js": "framework", "Next.js": "framework",
    "WordPress": "cms", "Joomla": "cms", "Drupal": "cms", "Ghost": "cms",
    "Magento": "cms", "PrestaShop": "cms", "TYPO3": "cms", "Shopify": "cms",
    "PHP": "language", "Python": "language", "Ruby": "language", "Java": "language",
    "Node.js": "language", "ASP.NET": "language",
}


class Wappalyzer(InfoGatheringTool):
    """Technology detection using python-Wappalyzer library (WSTG 4.1.8)."""

    async def execute(self, target_id: int, **kwargs: Any) -> ProbeResult:
        import asyncio
        host = kwargs.get("host")
        asset_id = kwargs.get("asset_id")
        if not host or not asset_id:
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={},
                               error="missing host or asset_id")
        try:
            from Wappalyzer import Wappalyzer as WapLib, WebPage
            webpage = await asyncio.get_event_loop().run_in_executor(
                None, WebPage.new_from_url, f"https://{host}"
            )
            wappalyzer = WapLib.latest()
            techs = await asyncio.get_event_loop().run_in_executor(
                None, wappalyzer.analyze, webpage
            )
        except Exception as exc:
            logger.error("wappalyzer failed", host=host, error=str(exc))
            return ProbeResult(probe="wappalyzer", obs_id=None, signals={}, error=str(exc))

        tech_names = list(techs) if isinstance(techs, (set, list)) else list(techs.keys())
        signals: dict[str, Any] = {"framework": [], "cms": [], "language": []}
        for name in tech_names:
            slot = _TECH_SLOTS.get(name)
            if slot:
                signals[slot].append({"src": "wappalyzer", "value": name, "w": 0.6})

        obs_id = await self.save_observation(
            asset_id=asset_id,
            tech_stack={"_probe": "wappalyzer", "host": host, "technologies": tech_names},
        )
        return ProbeResult(probe="wappalyzer", obs_id=obs_id, signals=signals)
```

- [ ] **Step 4: Commit**

```bash
git add workers/info_gathering/tools/naabu.py workers/info_gathering/tools/vhost_prober.py workers/info_gathering/tools/wappalyzer.py
git commit -m "fix(tools): fix save_location/save_observation signatures in naabu, vhost_prober; switch wappalyzer to python library"
```

---

## Task 12: Add error logging to silently-failing Stage 4 tools

**Files:**
- Modify: `workers/info_gathering/tools/subfinder.py`
- Modify: `workers/info_gathering/tools/assetfinder.py`
- Modify: `workers/info_gathering/tools/amass_passive.py`
- Modify: `workers/info_gathering/tools/amass_active.py`
- Modify: `workers/info_gathering/tools/massdns.py`
- Modify: `workers/info_gathering/tools/waybackurls.py`

- [ ] **Step 1: Fix subfinder.py**

Replace the `execute` method:

```python
    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["subfinder", "-d", target.base_domain, "-silent", "-json"]
        try:
            stdout = await self.run_subprocess(cmd)
        except Exception as exc:
            logger.error("subfinder failed", domain=target.base_domain, error=str(exc))
            return

        results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                if host:
                    results.append(host)
            except json.JSONDecodeError:
                results.append(line)

        for host in results:
            await self.save_asset(target_id, "subdomain", host, "subfinder")
```

Add `import json` at the top if not present. Also add `from workers.info_gathering.base_tool import InfoGatheringTool, logger` (replace the current import line to include `logger`).

- [ ] **Step 2: Fix assetfinder.py**

Replace `execute`:

```python
    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["assetfinder", "--subs-only", target.base_domain]
        try:
            stdout = await self.run_subprocess(cmd)
        except Exception as exc:
            logger.error("assetfinder failed", domain=target.base_domain, error=str(exc))
            return

        for line in stdout.strip().splitlines():
            host = line.strip()
            if host:
                await self.save_asset(target_id, "subdomain", host, "assetfinder")
```

Add `from workers.info_gathering.base_tool import InfoGatheringTool, logger`.

- [ ] **Step 3: Fix amass_passive.py**

```python
    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["amass", "enum", "-passive", "-d", target.base_domain]
        try:
            stdout = await self.run_subprocess(cmd, timeout=900)
        except Exception as exc:
            logger.error("amass_passive failed", domain=target.base_domain, error=str(exc))
            return

        for line in stdout.strip().splitlines():
            host = line.strip()
            if host:
                await self.save_asset(target_id, "subdomain", host, "amass_passive")
```

Add `from workers.info_gathering.base_tool import InfoGatheringTool, logger`.

- [ ] **Step 4: Fix amass_active.py**

```python
    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        cmd = ["amass", "enum", "-active", "-d", target.base_domain, "-brute"]
        try:
            stdout = await self.run_subprocess(cmd, timeout=1200)
        except Exception as exc:
            logger.error("amass_active failed", domain=target.base_domain, error=str(exc))
            return

        for line in stdout.strip().splitlines():
            host = line.strip()
            if host:
                await self.save_asset(target_id, "subdomain", host, "amass_active")
```

- [ ] **Step 5: Fix massdns.py — add error logging and guard missing resolvers file**

Replace the `execute` method's try block:

```python
        RESOLVERS = "/app/workers/info_gathering/resolvers.txt"
        if not os.path.exists(RESOLVERS):
            logger.error("massdns: resolvers file not found", path=RESOLVERS)
            return

        try:
            cmd = ["massdns", "-r", RESOLVERS, "-t", "A", "-o", "S", input_file]
            stdout = await self.run_subprocess(cmd, timeout=300)

            for line in stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    ip = parts[2]
                    await self.save_asset(target_id, "ip", ip, "massdns")
        except Exception as exc:
            logger.error("massdns failed", error=str(exc))
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)
```

Add `from workers.info_gathering.base_tool import InfoGatheringTool, logger` and ensure `import os` is present.

- [ ] **Step 6: Fix waybackurls.py — add error logging**

Replace the silent `except Exception: pass` blocks with:

```python
        try:
            stdout = await self.run_subprocess(cmd, timeout=300)
            for line in stdout.strip().splitlines():
                url = line.strip()
                if url and url.startswith("http"):
                    asset_type = classify_url(url)
                    await self.save_asset(target_id, asset_type, url, "waybackurls")
        except Exception as exc:
            logger.error("waybackurls failed", domain=target.base_domain, error=str(exc))
```

And in `_query_commoncrawl`:

```python
        except Exception as exc:
            logger.warning("commoncrawl query failed", domain=domain, error=str(exc))
```

Add `from workers.info_gathering.base_tool import InfoGatheringTool, logger`.

- [ ] **Step 7: Commit**

```bash
git add workers/info_gathering/tools/subfinder.py \
        workers/info_gathering/tools/assetfinder.py \
        workers/info_gathering/tools/amass_passive.py \
        workers/info_gathering/tools/amass_active.py \
        workers/info_gathering/tools/massdns.py \
        workers/info_gathering/tools/waybackurls.py
git commit -m "fix(tools): add error logging to Stage 4 subdomain enumeration tools"
```

---

## Task 13: Audit and fix Stage 1 tools (search_engine_recon)

**Files:**
- Modify: `workers/info_gathering/tools/dork_engine.py`
- Modify: `workers/info_gathering/tools/archive_prober.py`
- Modify: `workers/info_gathering/tools/cache_prober.py`
- Modify: `workers/info_gathering/tools/shodan_searcher.py`
- Modify: `workers/info_gathering/tools/censys_searcher.py`
- Modify: `workers/info_gathering/tools/securitytrails_searcher.py`

- [ ] **Step 1: Read each tool file and verify the four audit criteria**

For each tool, check:
1. Binary or API key available — tools using external APIs (`shodan_searcher`, `censys_searcher`, `securitytrails_searcher`) should check for their env var and log a warning (not error) if missing, then return early
2. Invocation correct — HTTP-based tools should use `aiohttp`; subprocess tools should use `run_subprocess`
3. `save_asset` / `save_observation` called with correct `asset_id` (not `target_id`)
4. `except Exception: return` replaced with `except Exception as exc: logger.error(...)`

Run:

```bash
cat workers/info_gathering/tools/dork_engine.py
cat workers/info_gathering/tools/archive_prober.py
cat workers/info_gathering/tools/cache_prober.py
cat workers/info_gathering/tools/shodan_searcher.py
cat workers/info_gathering/tools/censys_searcher.py
cat workers/info_gathering/tools/securitytrails_searcher.py
```

- [ ] **Step 2: Apply fixes to each file that fails any criterion**

For any tool with `except Exception: return` (no `as exc`, no logging), replace with:

```python
        except Exception as exc:
            logger.error("<tool_name> failed", domain=target.base_domain, error=str(exc))
            return
```

For API-key tools, add at the top of `execute`:

```python
        api_key = os.environ.get("SHODAN_API_KEY")  # or CENSYS_API_ID, SECURITYTRAILS_API_KEY
        if not api_key:
            logger.warning("shodan_searcher: SHODAN_API_KEY not set, skipping")
            return
```

- [ ] **Step 3: Commit any changes made**

```bash
git add workers/info_gathering/tools/dork_engine.py \
        workers/info_gathering/tools/archive_prober.py \
        workers/info_gathering/tools/cache_prober.py \
        workers/info_gathering/tools/shodan_searcher.py \
        workers/info_gathering/tools/censys_searcher.py \
        workers/info_gathering/tools/securitytrails_searcher.py
git commit -m "fix(tools): audit Stage 1 search_engine_recon tools — add error logging and API key guards"
```

---

## Task 14: Audit Stages 2–3 and Stages 5–12 tools

**Files:**
- `workers/info_gathering/tools/` — all remaining tool files not covered in Tasks 11–13

- [ ] **Step 1: Read and audit Stage 2 tools**

```bash
cat workers/info_gathering/tools/liveness_probe.py
cat workers/info_gathering/tools/banner_probe.py
cat workers/info_gathering/tools/header_order_probe.py
cat workers/info_gathering/tools/method_probe.py
cat workers/info_gathering/tools/error_page_probe.py
cat workers/info_gathering/tools/tls_probe.py
cat workers/info_gathering/tools/waf_probe.py
cat workers/info_gathering/tools/whatweb.py
```

Apply the same four audit criteria. Stage 2 tools return `ProbeResult` — ensure they return `ProbeResult(probe=..., obs_id=None, signals={}, error=str(exc))` on failure rather than raising or returning `None`.

- [ ] **Step 2: Read and audit Stage 3 tools**

```bash
cat workers/info_gathering/tools/metafile_parser.py
cat workers/info_gathering/tools/meta_tag_analyzer.py
```

Ensure HTTP errors and parsing failures are caught and returned as structured errors (not silent returns).

- [ ] **Step 3: Read and audit Stage 5 tools (review_comments)**

```bash
cat workers/info_gathering/tools/comment_harvester.py
cat workers/info_gathering/tools/metadata_extractor.py
cat workers/info_gathering/tools/js_secret_scanner.py
cat workers/info_gathering/tools/source_map_prober.py
cat workers/info_gathering/tools/redirect_body_inspector.py
```

- [ ] **Step 4: Read and audit Stage 6 tools (identify_entry_points)**

```bash
cat workers/info_gathering/tools/form_mapper.py
cat workers/info_gathering/tools/paramspider.py
cat workers/info_gathering/tools/httpx.py
cat workers/info_gathering/tools/websocket_prober.py
```

Note: `paramspider` is a Python package installed via pip — verify it exposes a CLI command `paramspider` in PATH, or that the tool uses it as a Python library.

- [ ] **Step 5: Read and audit Stage 7 (aggregate_entry_points)**

```bash
cat workers/info_gathering/tools/entry_point_aggregator.py
```

- [ ] **Step 6: Read and audit Stage 8 tools (map_execution_paths)**

```bash
cat workers/info_gathering/tools/katana.py
cat workers/info_gathering/tools/hakrawler.py
```

- [ ] **Step 7: Read and audit Stages 10–12 tools**

```bash
cat workers/info_gathering/tools/webanalyze.py        # already fixed in Task 11
cat workers/info_gathering/tools/cookie_fingerprinter.py
cat workers/info_gathering/tools/header_framework_probe.py
cat workers/info_gathering/tools/meta_generator_probe.py
cat workers/info_gathering/tools/framework_file_prober.py
cat workers/info_gathering/tools/architecture_modeler.py
cat workers/info_gathering/tools/application_mapper.py
cat workers/info_gathering/tools/attack_surface_analyzer.py
```

- [ ] **Step 8: Commit all fixes**

```bash
git add workers/info_gathering/tools/
git commit -m "fix(tools): audit and fix Stages 2-3 and 5-12 — error logging, correct API usage"
```

---

## Task 15: Rebuild Docker image and verify

- [ ] **Step 1: Rebuild the info_gathering image**

```bash
docker compose build info_gathering
```

Expected: build completes without errors. Watch for any `go install` failures for `amass` — it is a large install that can take 3–5 minutes.

- [ ] **Step 2: Verify binaries are present in the container**

```bash
docker compose run --rm info_gathering which amass subfinder assetfinder naabu katana hakrawler massdns waybackurls ffuf webanalyze
```

Expected: each line shows `/root/go/bin/<tool>` or `/usr/local/bin/<tool>`

- [ ] **Step 3: Verify resolvers.txt is present**

```bash
docker compose run --rm info_gathering ls /app/workers/info_gathering/resolvers.txt
```

Expected: file listed

- [ ] **Step 4: Commit**

```bash
git commit --allow-empty -m "chore: verified Docker build with all tool binaries"
```

---

## Task 16: Live browser testing

- [ ] **Step 1: Start the full stack with test overlay**

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
```

Wait for all containers to be healthy:

```bash
docker compose ps
```

Expected: all services show `healthy` or `running`

- [ ] **Step 2: Run Playwright against the assets table**

Using browser automation tools (`mcp__claude-in-chrome__*`):
1. Navigate to `http://localhost:3000`
2. Select an active campaign
3. Navigate to `/campaign/assets`
4. Verify loading indicator shows `Loading N / total…`
5. Verify all assets load (count matches home page counter)
6. Capture any console errors with `read_console_messages`

- [ ] **Step 3: Test asset detail page**

1. Click any asset row in the assets table
2. Verify navigation to `/campaign/assets/[id]`
3. Verify header shows asset value in monospace
4. Verify Directory Tree panel renders (or shows empty-state message if no URL paths)
5. Verify Ports panel renders on the right
6. Click a tree node → verify side-drawer slides in with type, scope, source tool data
7. Click a port → verify side-drawer shows port, protocol, service, state
8. Click X to close drawer
9. Capture console errors

- [ ] **Step 4: Test C2 page**

1. Navigate to `/campaign/c2`
2. Verify Asset Tree section is gone
3. Verify QueueHealthWidget is gone
4. Verify Campaign Timeline spans full width
5. Capture console errors

- [ ] **Step 5: Record GIF of the asset detail page interaction**

Using `mcp__claude-in-chrome__gif_creator`: record the flow from the assets table → click asset → tree expands → click node → drawer opens → click port → drawer updates.

- [ ] **Step 6: Run backend e2e tests**

```bash
pytest tests/e2e/ --e2e -v
```

Expected: all existing tests pass; no regressions

- [ ] **Step 7: Verify path_nodes population**

After a live scan or seeded data:

```bash
docker compose exec postgres psql -U webbh_admin -d webbh -c "SELECT COUNT(*), node_type FROM path_nodes GROUP BY node_type;"
```

Expected: rows exist grouped by type (directory, url, form, etc.)

- [ ] **Step 8: Final commit**

```bash
git add .
git commit -m "test: live browser verification of assets detail page, C2 cleanup, path_nodes population"
```
