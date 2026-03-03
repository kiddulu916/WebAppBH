# Phase 3: C2 Dashboard Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the Next.js C2 dashboard end-to-end — add orchestrator GET endpoints, fix existing bugs, wire data tables to real APIs, add SSE proxy, campaign picker, settings drawer, alert dropdown, and status board.

**Architecture:** The orchestrator (FastAPI on port 8001) owns all DB access. The dashboard (Next.js on port 3000) consumes orchestrator REST endpoints and proxies SSE through a server-side route handler. Zustand manages client state with localStorage persistence. All new endpoints follow existing patterns in `orchestrator/main.py`.

**Tech Stack:** Python 3 / FastAPI / SQLAlchemy async (orchestrator), Next.js 16 / TypeScript / Tailwind CSS v4 / Zustand / TanStack Table / Sonner / Lucide (dashboard)

**Design doc:** `docs/plans/design/2026-03-03-phase3-dashboard-design.md`

---

## Task 1: Orchestrator GET Endpoints — Targets & Assets

**Files:**
- Modify: `orchestrator/main.py:1-9` (docstring) and append after line 278
- Test: `tests/test_main.py`

**Step 1: Write failing tests for GET /targets and GET /assets**

Add to `tests/test_main.py`:

```python
# --- Phase 3: GET endpoints ---

@pytest.mark.asyncio
async def test_get_targets_returns_all(db, client):
    async with get_session() as session:
        session.add(Target(company_name="Corp1", base_domain="corp1.com"))
        session.add(Target(company_name="Corp2", base_domain="corp2.com"))
        await session.commit()

    resp = await client.get("/api/v1/targets", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["targets"]) == 2
    assert data["targets"][0]["company_name"] == "Corp1"


@pytest.mark.asyncio
async def test_get_targets_empty(db, client):
    resp = await client.get("/api/v1/targets", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    assert resp.json()["targets"] == []


@pytest.mark.asyncio
async def test_get_assets_requires_target_id(db, client):
    resp = await client.get("/api/v1/assets", headers=API_KEY_HEADER)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_assets_returns_with_locations(db, client):
    async with get_session() as session:
        t = Target(company_name="AssetCorp", base_domain="asset.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Asset(target_id=t.id, asset_type="subdomain", asset_value="sub.asset.com", source_tool="amass")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        session.add(Location(asset_id=a.id, port=443, protocol="tcp", service="https", state="open"))
        await session.commit()

    resp = await client.get(f"/api/v1/assets?target_id={t.id}", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    assets = resp.json()["assets"]
    assert len(assets) == 1
    assert assets[0]["asset_value"] == "sub.asset.com"
    assert len(assets[0]["locations"]) == 1
    assert assets[0]["locations"][0]["port"] == 443
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py::test_get_targets_returns_all tests/test_main.py::test_get_assets_returns_with_locations -v`
Expected: FAIL — 404 (no route matched)

**Step 3: Implement GET /targets and GET /assets**

Add the `Vulnerability` import at line 28 (already imported as `from lib_webbh import ... Vulnerability` — check it's there. Also add `CloudAsset, Location` to imports).

Update the import at `orchestrator/main.py:28-38`:

```python
from lib_webbh import (
    Alert,
    Asset,
    Base,
    CloudAsset,
    JobState,
    Location,
    Target,
    Vulnerability,
    get_engine,
    get_session,
    push_task,
    setup_logger,
)
```

Add after the SSE endpoint section (after line 278), before `_generate_tool_configs`:

```python
# ---------------------------------------------------------------------------
# GET /api/v1/targets — list all campaigns
# ---------------------------------------------------------------------------
@app.get("/api/v1/targets")
async def list_targets():
    async with get_session() as session:
        result = await session.execute(select(Target).order_by(Target.created_at.desc()))
        targets = result.scalars().all()

    return {
        "targets": [
            {
                "id": t.id,
                "company_name": t.company_name,
                "base_domain": t.base_domain,
                "target_profile": t.target_profile,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
            }
            for t in targets
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/assets — assets for a target (with locations eager-loaded)
# ---------------------------------------------------------------------------
@app.get("/api/v1/assets")
async def list_assets(target_id: int):
    from sqlalchemy.orm import selectinload

    async with get_session() as session:
        stmt = (
            select(Asset)
            .where(Asset.target_id == target_id)
            .options(selectinload(Asset.locations))
            .order_by(Asset.created_at.desc())
        )
        result = await session.execute(stmt)
        assets = result.scalars().all()

    return {
        "assets": [
            {
                "id": a.id,
                "target_id": a.target_id,
                "asset_type": a.asset_type,
                "asset_value": a.asset_value,
                "source_tool": a.source_tool,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                "locations": [
                    {
                        "id": loc.id,
                        "port": loc.port,
                        "protocol": loc.protocol,
                        "service": loc.service,
                        "state": loc.state,
                    }
                    for loc in a.locations
                ],
            }
            for a in assets
        ],
    }
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py::test_get_targets_returns_all tests/test_main.py::test_get_targets_empty tests/test_main.py::test_get_assets_requires_target_id tests/test_main.py::test_get_assets_returns_with_locations -v`
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "feat(orchestrator): add GET /targets and GET /assets endpoints"
```

---

## Task 2: Orchestrator GET Endpoints — Vulnerabilities, Cloud Assets, Alerts

**Files:**
- Modify: `orchestrator/main.py` (append after assets endpoint)
- Test: `tests/test_main.py`

**Step 1: Write failing tests**

Add to `tests/test_main.py`:

```python
@pytest.mark.asyncio
async def test_get_vulnerabilities_with_severity_filter(db, client):
    from lib_webbh.database import Vulnerability as VulnModel
    async with get_session() as session:
        t = Target(company_name="VulnCorp", base_domain="vuln.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        session.add(VulnModel(target_id=t.id, severity="critical", title="RCE in login"))
        session.add(VulnModel(target_id=t.id, severity="low", title="Missing header"))
        await session.commit()

    resp = await client.get(f"/api/v1/vulnerabilities?target_id={t.id}&severity=critical", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    vulns = resp.json()["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["title"] == "RCE in login"


@pytest.mark.asyncio
async def test_get_vulnerabilities_all(db, client):
    from lib_webbh.database import Vulnerability as VulnModel
    async with get_session() as session:
        t = Target(company_name="VulnCorp2", base_domain="vuln2.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        session.add(VulnModel(target_id=t.id, severity="high", title="XSS"))
        session.add(VulnModel(target_id=t.id, severity="medium", title="CSRF"))
        await session.commit()

    resp = await client.get(f"/api/v1/vulnerabilities?target_id={t.id}", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    assert len(resp.json()["vulnerabilities"]) == 2


@pytest.mark.asyncio
async def test_get_cloud_assets(db, client):
    async with get_session() as session:
        t = Target(company_name="CloudCorp", base_domain="cloud.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        session.add(CloudAsset(target_id=t.id, provider="AWS", asset_type="s3_bucket", url="s3://cloud-corp-backup", is_public=True))
        await session.commit()

    resp = await client.get(f"/api/v1/cloud_assets?target_id={t.id}", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    ca = resp.json()["cloud_assets"]
    assert len(ca) == 1
    assert ca[0]["provider"] == "AWS"
    assert ca[0]["is_public"] is True


@pytest.mark.asyncio
async def test_get_alerts_filtered_by_is_read(db, client):
    async with get_session() as session:
        t = Target(company_name="AlertCorp", base_domain="alert.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        session.add(Alert(target_id=t.id, alert_type="CRITICAL_ALERT", message="exposed .env", is_read=False))
        session.add(Alert(target_id=t.id, alert_type="ZOMBIE_RESTART", message="worker restarted", is_read=True))
        await session.commit()

    resp = await client.get(f"/api/v1/alerts?target_id={t.id}&is_read=false", headers=API_KEY_HEADER)
    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["message"] == "exposed .env"


@pytest.mark.asyncio
async def test_patch_alert_mark_read(db, client):
    async with get_session() as session:
        t = Target(company_name="PatchCorp", base_domain="patch.com")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        a = Alert(target_id=t.id, alert_type="CRITICAL_ALERT", message="open bucket", is_read=False)
        session.add(a)
        await session.commit()
        await session.refresh(a)
        alert_id = a.id

    resp = await client.patch(f"/api/v1/alerts/{alert_id}", json={"is_read": True}, headers=API_KEY_HEADER)
    assert resp.status_code == 200
    assert resp.json()["is_read"] is True
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py::test_get_vulnerabilities_with_severity_filter tests/test_main.py::test_get_cloud_assets tests/test_main.py::test_get_alerts_filtered_by_is_read tests/test_main.py::test_patch_alert_mark_read -v`
Expected: FAIL — 404 or 405

**Step 3: Implement the endpoints**

Add to `orchestrator/main.py` after the assets endpoint:

```python
# ---------------------------------------------------------------------------
# GET /api/v1/vulnerabilities — vulns for a target
# ---------------------------------------------------------------------------
@app.get("/api/v1/vulnerabilities")
async def list_vulnerabilities(target_id: int, severity: str | None = None):
    from sqlalchemy.orm import selectinload

    async with get_session() as session:
        stmt = (
            select(Vulnerability)
            .where(Vulnerability.target_id == target_id)
            .options(selectinload(Vulnerability.asset))
            .order_by(Vulnerability.created_at.desc())
        )
        if severity:
            stmt = stmt.where(Vulnerability.severity == severity)
        result = await session.execute(stmt)
        vulns = result.scalars().all()

    return {
        "vulnerabilities": [
            {
                "id": v.id,
                "target_id": v.target_id,
                "asset_id": v.asset_id,
                "asset_value": v.asset.asset_value if v.asset else None,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
                "poc": v.poc,
                "source_tool": v.source_tool,
                "created_at": v.created_at.isoformat() if v.created_at else None,
                "updated_at": v.updated_at.isoformat() if v.updated_at else None,
            }
            for v in vulns
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/cloud_assets — cloud assets for a target
# ---------------------------------------------------------------------------
@app.get("/api/v1/cloud_assets")
async def list_cloud_assets(target_id: int):
    async with get_session() as session:
        stmt = (
            select(CloudAsset)
            .where(CloudAsset.target_id == target_id)
            .order_by(CloudAsset.created_at.desc())
        )
        result = await session.execute(stmt)
        items = result.scalars().all()

    return {
        "cloud_assets": [
            {
                "id": c.id,
                "target_id": c.target_id,
                "provider": c.provider,
                "asset_type": c.asset_type,
                "url": c.url,
                "is_public": c.is_public,
                "findings": c.findings,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            }
            for c in items
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/v1/alerts — alerts for a target
# ---------------------------------------------------------------------------
@app.get("/api/v1/alerts")
async def list_alerts(target_id: int, is_read: bool | None = None):
    async with get_session() as session:
        stmt = (
            select(Alert)
            .where(Alert.target_id == target_id)
            .order_by(Alert.created_at.desc())
        )
        if is_read is not None:
            stmt = stmt.where(Alert.is_read == is_read)
        result = await session.execute(stmt)
        alerts = result.scalars().all()

    return {
        "alerts": [
            {
                "id": a.id,
                "target_id": a.target_id,
                "vulnerability_id": a.vulnerability_id,
                "alert_type": a.alert_type,
                "message": a.message,
                "is_read": a.is_read,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }


# ---------------------------------------------------------------------------
# PATCH /api/v1/alerts/{alert_id} — mark alert read/unread
# ---------------------------------------------------------------------------
class AlertUpdate(BaseModel):
    is_read: bool


@app.patch("/api/v1/alerts/{alert_id}")
async def update_alert(alert_id: int, body: AlertUpdate):
    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert.is_read = body.is_read
        await session.commit()

    return {"id": alert_id, "is_read": body.is_read}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py::test_get_vulnerabilities_with_severity_filter tests/test_main.py::test_get_vulnerabilities_all tests/test_main.py::test_get_cloud_assets tests/test_main.py::test_get_alerts_filtered_by_is_read tests/test_main.py::test_patch_alert_mark_read -v`
Expected: 5 PASSED

**Step 5: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "feat(orchestrator): add GET vulns, cloud_assets, alerts + PATCH alerts"
```

---

## Task 3: Orchestrator PATCH /targets/{id} — Update Target Profile

**Files:**
- Modify: `orchestrator/main.py`
- Test: `tests/test_main.py`

**Step 1: Write failing test**

```python
@pytest.mark.asyncio
async def test_patch_target_profile(db, client, tmp_path):
    with patch("orchestrator.main.SHARED_CONFIG", tmp_path):
        resp = await client.post("/api/v1/targets", json={
            "company_name": "PatchTarget",
            "base_domain": "patchtarget.com",
            "target_profile": {"rate_limits": {"pps": 50}, "custom_headers": {"X-Old": "val"}},
        }, headers=API_KEY_HEADER)
        tid = resp.json()["target_id"]

        resp = await client.patch(f"/api/v1/targets/{tid}", json={
            "custom_headers": {"Authorization": "Bearer new"},
            "rate_limits": {"pps": 100},
        }, headers=API_KEY_HEADER)
    assert resp.status_code == 200
    profile = resp.json()["target_profile"]
    assert profile["custom_headers"] == {"Authorization": "Bearer new"}
    assert profile["rate_limits"] == {"pps": 100}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py::test_patch_target_profile -v`
Expected: FAIL — 405 Method Not Allowed

**Step 3: Implement PATCH /targets/{id}**

Add to `orchestrator/main.py`:

```python
# ---------------------------------------------------------------------------
# PATCH /api/v1/targets/{target_id} — update target profile
# ---------------------------------------------------------------------------
class TargetProfileUpdate(BaseModel):
    custom_headers: Optional[dict] = None
    rate_limits: Optional[dict] = None


@app.patch("/api/v1/targets/{target_id}")
async def update_target_profile(target_id: int, body: TargetProfileUpdate):
    async with get_session() as session:
        result = await session.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        profile = target.target_profile or {}
        if body.custom_headers is not None:
            profile["custom_headers"] = body.custom_headers
        if body.rate_limits is not None:
            profile["rate_limits"] = body.rate_limits
        target.target_profile = profile
        await session.commit()
        await session.refresh(target)

    # Rewrite config files
    _generate_tool_configs(target_id, target.target_profile or {})

    return {
        "target_id": target_id,
        "target_profile": target.target_profile,
    }
```

**Step 4: Run test to verify it passes**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py::test_patch_target_profile -v`
Expected: PASS

**Step 5: Run full orchestrator test suite**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py -v`
Expected: All PASSED

**Step 6: Commit**

```bash
git add orchestrator/main.py tests/test_main.py
git commit -m "feat(orchestrator): add PATCH /targets/{id} for profile updates"
```

---

## Task 4: Dashboard Bug Fixes — Types & API Client

**Files:**
- Modify: `dashboard/src/types/schema.ts:16` — add PAUSED, STOPPED
- Modify: `dashboard/src/lib/api.ts:3` — fix port; lines 63-86 — add methods

**Step 1: Fix JobStatus type**

In `dashboard/src/types/schema.ts`, change line 16:

```typescript
export type JobStatus = "QUEUED" | "RUNNING" | "PAUSED" | "STOPPED" | "COMPLETED" | "FAILED";
```

**Step 2: Fix api.ts — port and add methods**

In `dashboard/src/lib/api.ts`, change line 3:

```typescript
const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";
```

Add response interfaces after `ControlResponse` (after line 57):

```typescript
/* ------------------------------------------------------------------ */
/* Assets                                                             */
/* ------------------------------------------------------------------ */

interface AssetWithLocations {
  id: number;
  target_id: number;
  asset_type: string;
  asset_value: string;
  source_tool: string | null;
  created_at: string | null;
  updated_at: string | null;
  locations: {
    id: number;
    port: number;
    protocol: string | null;
    service: string | null;
    state: string | null;
  }[];
}

interface AssetsResponse {
  assets: AssetWithLocations[];
}

/* ------------------------------------------------------------------ */
/* Vulnerabilities                                                    */
/* ------------------------------------------------------------------ */

interface VulnWithAsset {
  id: number;
  target_id: number;
  asset_id: number | null;
  asset_value: string | null;
  severity: string;
  title: string;
  description: string | null;
  poc: string | null;
  source_tool: string | null;
  created_at: string | null;
  updated_at: string | null;
}

interface VulnerabilitiesResponse {
  vulnerabilities: VulnWithAsset[];
}

/* ------------------------------------------------------------------ */
/* Cloud Assets                                                       */
/* ------------------------------------------------------------------ */

interface CloudAssetsResponse {
  cloud_assets: import("@/types/schema").CloudAsset[];
}

/* ------------------------------------------------------------------ */
/* Alerts                                                             */
/* ------------------------------------------------------------------ */

interface AlertsResponse {
  alerts: import("@/types/schema").Alert[];
}

/* ------------------------------------------------------------------ */
/* Targets (list)                                                     */
/* ------------------------------------------------------------------ */

interface TargetsResponse {
  targets: import("@/types/schema").Target[];
}
```

Extend the `api` object — replace the existing one (lines 63-86) with:

```typescript
export const api = {
  createTarget(data: CreateTargetPayload) {
    return request<CreateTargetResponse>("/api/v1/targets", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getTargets() {
    return request<TargetsResponse>("/api/v1/targets");
  },

  getStatus(targetId?: number) {
    const qs = targetId != null ? `?target_id=${targetId}` : "";
    return request<StatusResponse>(`/api/v1/status${qs}`);
  },

  getAssets(targetId: number) {
    return request<AssetsResponse>(`/api/v1/assets?target_id=${targetId}`);
  },

  getVulnerabilities(targetId: number, severity?: string) {
    let qs = `?target_id=${targetId}`;
    if (severity) qs += `&severity=${severity}`;
    return request<VulnerabilitiesResponse>(`/api/v1/vulnerabilities${qs}`);
  },

  getCloudAssets(targetId: number) {
    return request<CloudAssetsResponse>(`/api/v1/cloud_assets?target_id=${targetId}`);
  },

  getAlerts(targetId: number, isRead?: boolean) {
    let qs = `?target_id=${targetId}`;
    if (isRead !== undefined) qs += `&is_read=${isRead}`;
    return request<AlertsResponse>(`/api/v1/alerts${qs}`);
  },

  markAlertRead(alertId: number) {
    return request<{ id: number; is_read: boolean }>(`/api/v1/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ is_read: true }),
    });
  },

  updateTargetProfile(targetId: number, profile: { custom_headers?: Record<string, string>; rate_limits?: Record<string, number> }) {
    return request<{ target_id: number; target_profile: import("@/types/schema").TargetProfile }>(`/api/v1/targets/${targetId}`, {
      method: "PATCH",
      body: JSON.stringify(profile),
    });
  },

  controlWorker(containerName: string, action: "pause" | "stop" | "restart" | "unpause") {
    return request<ControlResponse>("/api/v1/control", {
      method: "POST",
      body: JSON.stringify({ container_name: containerName, action }),
    });
  },

  sseUrl(targetId: number) {
    return `${BASE_URL}/api/v1/stream/${targetId}`;
  },
};
```

**Step 3: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 4: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/types/schema.ts dashboard/src/lib/api.ts
git commit -m "fix(dashboard): add PAUSED/STOPPED to JobStatus, fix port, add API methods"
```

---

## Task 5: SSE Proxy Route

**Files:**
- Create: `dashboard/src/app/api/sse/[targetId]/route.ts`
- Modify: `dashboard/src/hooks/useEventStream.ts:25-26`

**Step 1: Create the SSE proxy route**

Create `dashboard/src/app/api/sse/[targetId]/route.ts`:

```typescript
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ targetId: string }> },
) {
  const { targetId } = await params;
  const abort = new AbortController();

  const upstream = await fetch(`${API_URL}/api/v1/stream/${targetId}`, {
    headers: { "X-API-KEY": API_KEY },
    signal: abort.signal,
  });

  if (!upstream.ok || !upstream.body) {
    return new Response("Upstream SSE unavailable", { status: 502 });
  }

  const stream = new ReadableStream({
    async start(controller) {
      const reader = upstream.body!.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          controller.enqueue(value);
        }
      } catch {
        // client disconnected or upstream closed
      } finally {
        controller.close();
        abort.abort();
      }
    },
    cancel() {
      abort.abort();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
```

**Step 2: Update useEventStream to use proxy**

In `dashboard/src/hooks/useEventStream.ts`, replace line 25-26:

```typescript
// OLD:
// const url = api.sseUrl(targetId);
// const es = new EventSource(url);

// NEW:
const url = `/api/sse/${targetId}`;
const es = new EventSource(url);
```

Remove the `api` import from line 5 (no longer needed):

```typescript
// OLD:
// import { api } from "@/lib/api";

// Remove this line entirely — api is no longer used in this hook.
```

**Step 3: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 4: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/app/api/sse/[targetId]/route.ts dashboard/src/hooks/useEventStream.ts
git commit -m "feat(dashboard): add SSE proxy route, remove direct orchestrator SSE"
```

---

## Task 6: WorkerConsole — PAUSED/STOPPED Support

**Files:**
- Modify: `dashboard/src/components/c2/WorkerConsole.tsx:15-27` (status maps) and `:88-131` (action buttons)

**Step 1: Update status color maps**

Replace lines 15-27:

```typescript
const STATUS_COLORS: Record<JobStatus, string> = {
  RUNNING: "text-success",
  QUEUED: "text-warning",
  PAUSED: "text-warning",
  STOPPED: "text-text-muted",
  COMPLETED: "text-text-muted",
  FAILED: "text-danger",
};

const STATUS_DOT: Record<JobStatus, string> = {
  RUNNING: "bg-success",
  QUEUED: "bg-warning",
  PAUSED: "bg-warning",
  STOPPED: "bg-text-muted",
  COMPLETED: "bg-text-muted",
  FAILED: "bg-danger",
};
```

**Step 2: Update handleAction type and add PAUSED button**

Replace the `handleAction` function signature (line 32-35):

```typescript
  async function handleAction(
    containerName: string,
    action: "pause" | "stop" | "restart" | "unpause",
  ) {
```

Add PAUSED action buttons after the RUNNING block (after line 109, before the FAILED/COMPLETED block):

```typescript
                  {job.status === "PAUSED" && (
                    <>
                      <button
                        onClick={() =>
                          handleAction(job.container_name, "unpause")
                        }
                        title="Resume"
                        className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface hover:text-success"
                      >
                        <Play className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() =>
                          handleAction(job.container_name, "stop")
                        }
                        title="Stop"
                        className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface hover:text-danger"
                      >
                        <Square className="h-3.5 w-3.5" />
                      </button>
                    </>
                  )}
```

Also add a restart button for STOPPED jobs. Update the FAILED/COMPLETED block (line 110) to also include STOPPED:

```typescript
                  {(job.status === "FAILED" || job.status === "COMPLETED" || job.status === "STOPPED") && (
```

**Step 3: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 4: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/components/c2/WorkerConsole.tsx
git commit -m "fix(dashboard): add PAUSED/STOPPED status support to WorkerConsole"
```

---

## Task 7: WorkerFeed Timestamp Fix

**Files:**
- Modify: `dashboard/src/components/c2/WorkerFeed.tsx:34-36`

**Step 1: Fix timestamp to use event data**

The SSE events have a `target_id` and various fields but no explicit `timestamp` field. We should capture the time when the event is received in the hook, not at render time.

First, add a `timestamp` field to SSEEvent. In `dashboard/src/types/events.ts`, update the interface (line 9):

```typescript
export interface SSEEvent {
  event: SSEEventType;
  target_id: number;
  timestamp?: string; // ISO-8601, added client-side on receipt
  [key: string]: unknown;
}
```

Then in `dashboard/src/hooks/useEventStream.ts`, add timestamp on receipt. Update the `handleEvent` function — in the `try` block after `const data: SSEEvent = JSON.parse(e.data);` add:

```typescript
        data.timestamp = new Date().toISOString();
```

Now fix `WorkerFeed.tsx` line 34-36 — replace:

```typescript
              <span className="shrink-0 text-text-muted">
                {new Date().toLocaleTimeString()}
              </span>
```

With:

```typescript
              <span className="shrink-0 text-text-muted">
                {evt.timestamp
                  ? new Date(evt.timestamp).toLocaleTimeString()
                  : "—"}
              </span>
```

**Step 2: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/types/events.ts dashboard/src/hooks/useEventStream.ts dashboard/src/components/c2/WorkerFeed.tsx
git commit -m "fix(dashboard): use receipt timestamp in WorkerFeed instead of render time"
```

---

## Task 8: Campaign Store — Add Alert Count & Refresh Helpers

**Files:**
- Modify: `dashboard/src/stores/campaign.ts`

**Step 1: Extend the store**

Replace `dashboard/src/stores/campaign.ts` entirely:

```typescript
import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Target, JobState } from "@/types/schema";

interface CampaignState {
  /* data */
  activeTarget: Target | null;
  currentPhase: string | null;
  jobs: JobState[];
  unreadAlerts: number;

  /* connectivity */
  connected: boolean;

  /* actions */
  setActiveTarget: (target: Target | null) => void;
  setCurrentPhase: (phase: string | null) => void;
  setJobs: (jobs: JobState[]) => void;
  setConnected: (v: boolean) => void;
  setUnreadAlerts: (count: number) => void;
  incrementUnreadAlerts: () => void;
  decrementUnreadAlerts: () => void;
}

export const useCampaignStore = create<CampaignState>()(
  persist(
    (set) => ({
      activeTarget: null,
      currentPhase: null,
      jobs: [],
      unreadAlerts: 0,
      connected: false,

      setActiveTarget: (target) => set({ activeTarget: target }),
      setCurrentPhase: (phase) => set({ currentPhase: phase }),
      setJobs: (jobs) => set({ jobs }),
      setConnected: (v) => set({ connected: v }),
      setUnreadAlerts: (count) => set({ unreadAlerts: count }),
      incrementUnreadAlerts: () =>
        set((s) => ({ unreadAlerts: s.unreadAlerts + 1 })),
      decrementUnreadAlerts: () =>
        set((s) => ({ unreadAlerts: Math.max(0, s.unreadAlerts - 1) })),
    }),
    {
      name: "webbh-campaign",
      partialize: (s) => ({
        activeTarget: s.activeTarget,
        currentPhase: s.currentPhase,
      }),
    },
  ),
);
```

**Step 2: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/stores/campaign.ts
git commit -m "feat(dashboard): add alert count to campaign store"
```

---

## Task 9: Alert Dropdown Component

**Files:**
- Create: `dashboard/src/components/layout/AlertDropdown.tsx`
- Modify: `dashboard/src/components/layout/StatusBar.tsx`

**Step 1: Create AlertDropdown**

Create `dashboard/src/components/layout/AlertDropdown.tsx`:

```typescript
"use client";

import { useEffect, useRef, useState } from "react";
import { Bell } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Alert } from "@/types/schema";

export default function AlertDropdown() {
  const { activeTarget, unreadAlerts, setUnreadAlerts, decrementUnreadAlerts } =
    useCampaignStore();
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  // Fetch unread count on mount and when target changes
  useEffect(() => {
    if (!activeTarget) return;
    api
      .getAlerts(activeTarget.id, false)
      .then((res) => setUnreadAlerts(res.alerts.length))
      .catch(() => {});
  }, [activeTarget, setUnreadAlerts]);

  // Fetch all alerts when dropdown opens
  useEffect(() => {
    if (!open || !activeTarget) return;
    api
      .getAlerts(activeTarget.id)
      .then((res) => setAlerts(res.alerts))
      .catch(() => {});
  }, [open, activeTarget]);

  async function markRead(alertId: number) {
    await api.markAlertRead(alertId);
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, is_read: true } : a)),
    );
    decrementUnreadAlerts();
  }

  function timeAgo(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="relative rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface hover:text-text-primary"
      >
        <Bell className="h-4 w-4" />
        {unreadAlerts > 0 && (
          <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-bold text-white">
            {unreadAlerts > 99 ? "99+" : unreadAlerts}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 rounded-lg border border-border bg-bg-secondary shadow-lg">
          <div className="border-b border-border px-3 py-2">
            <span className="text-xs font-medium text-text-secondary">
              Alerts
            </span>
          </div>
          <div className="max-h-72 overflow-y-auto">
            {alerts.length === 0 ? (
              <p className="px-3 py-4 text-center text-xs text-text-muted">
                No alerts
              </p>
            ) : (
              alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`flex items-start gap-2 border-b border-border px-3 py-2.5 ${
                    alert.is_read ? "opacity-50" : ""
                  }`}
                >
                  <span
                    className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                      alert.alert_type === "CRITICAL_ALERT"
                        ? "bg-danger"
                        : "bg-warning"
                    }`}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium text-text-primary">
                      {alert.alert_type}
                    </p>
                    <p className="truncate text-xs text-text-muted">
                      {alert.message}
                    </p>
                    <span className="text-[10px] text-text-muted">
                      {timeAgo(alert.created_at)}
                    </span>
                  </div>
                  {!alert.is_read && (
                    <button
                      onClick={() => markRead(alert.id)}
                      className="shrink-0 text-[10px] text-accent hover:underline"
                    >
                      Read
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
```

**Step 2: Add AlertDropdown to StatusBar**

In `dashboard/src/components/layout/StatusBar.tsx`, add import at line 3:

```typescript
import AlertDropdown from "@/components/layout/AlertDropdown";
```

Insert `<AlertDropdown />` into the right section, before the connection indicator div (before line 32). Replace lines 31-46:

```typescript
      {/* Right — alerts + connection indicator */}
      <div className="flex items-center gap-3">
        <AlertDropdown />
        <div className="flex items-center gap-1.5">
          {connected ? (
            <>
              <Wifi className="h-3.5 w-3.5 text-success" />
              <span className="text-xs text-success">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-danger" />
              <span className="text-xs text-danger">Disconnected</span>
            </>
          )}
        </div>
        <Activity className="h-4 w-4 animate-pulse text-accent" />
      </div>
```

**Step 3: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 4: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/components/layout/AlertDropdown.tsx dashboard/src/components/layout/StatusBar.tsx
git commit -m "feat(dashboard): add AlertDropdown with unread badge to StatusBar"
```

---

## Task 10: Campaign Picker & Home Page

**Files:**
- Create: `dashboard/src/components/campaign/CampaignPicker.tsx`
- Modify: `dashboard/src/app/page.tsx`

**Step 1: Create CampaignPicker**

Create `dashboard/src/components/campaign/CampaignPicker.tsx`:

```typescript
"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Plus, Globe } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Target } from "@/types/schema";

export default function CampaignPicker() {
  const router = useRouter();
  const setActiveTarget = useCampaignStore((s) => s.setActiveTarget);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getTargets()
      .then((res) => {
        setTargets(res.targets);
        if (res.targets.length === 0) {
          router.push("/campaign");
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [router]);

  function selectCampaign(target: Target) {
    setActiveTarget(target);
    router.push("/campaign/c2");
  }

  if (loading) {
    return (
      <div className="flex h-40 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-accent" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-text-primary">
          Select a Campaign
        </h2>
        <p className="text-sm text-text-muted">
          Choose an existing campaign or start a new one
        </p>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {targets.map((t) => (
          <button
            key={t.id}
            onClick={() => selectCampaign(t)}
            className="group rounded-lg border border-border bg-bg-secondary p-4 text-left transition-colors hover:border-accent/50"
          >
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-accent" />
              <span className="text-sm font-medium text-text-primary group-hover:text-accent">
                {t.base_domain}
              </span>
            </div>
            <p className="mt-1 text-xs text-text-muted">{t.company_name}</p>
            {t.created_at && (
              <p className="mt-2 text-[10px] text-text-muted">
                {new Date(t.created_at).toLocaleDateString()}
              </p>
            )}
          </button>
        ))}
        <button
          onClick={() => router.push("/campaign")}
          className="group flex items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-bg-secondary p-4 transition-colors hover:border-accent/50"
        >
          <Plus className="h-4 w-4 text-text-muted group-hover:text-accent" />
          <span className="text-sm text-text-muted group-hover:text-accent">
            New Campaign
          </span>
        </button>
      </div>
    </div>
  );
}
```

**Step 2: Update home page to show picker when no active target**

Replace `dashboard/src/app/page.tsx` entirely:

```typescript
"use client";

import Link from "next/link";
import { Target, Activity, Shield, Cloud } from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import CampaignPicker from "@/components/campaign/CampaignPicker";

export default function DashboardHome() {
  const { activeTarget } = useCampaignStore();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Dashboard</h1>
        <p className="mt-1 text-sm text-text-secondary">
          WebAppBH Bug Bounty Framework — Command & Control
        </p>
      </div>

      {!activeTarget ? (
        <CampaignPicker />
      ) : (
        <>
          {/* Quick Actions */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Link
              href="/campaign"
              className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
            >
              <Target className="mb-3 h-6 w-6 text-accent" />
              <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
                New Campaign
              </h3>
              <p className="mt-1 text-xs text-text-muted">
                Initialize a new target scan
              </p>
            </Link>

            <Link
              href="/campaign/c2"
              className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
            >
              <Activity className="mb-3 h-6 w-6 text-success" />
              <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
                C2 Console
              </h3>
              <p className="mt-1 text-xs text-text-muted">
                Monitor and control workers
              </p>
            </Link>

            <Link
              href="/campaign/vulns"
              className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
            >
              <Shield className="mb-3 h-6 w-6 text-danger" />
              <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
                Vulnerabilities
              </h3>
              <p className="mt-1 text-xs text-text-muted">
                Review discovered findings
              </p>
            </Link>

            <Link
              href="/campaign/cloud"
              className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
            >
              <Cloud className="mb-3 h-6 w-6 text-warning" />
              <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
                Cloud Assets
              </h3>
              <p className="mt-1 text-xs text-text-muted">
                AWS / Azure / GCP findings
              </p>
            </Link>
          </div>

          {/* Active Campaign Summary */}
          <div className="rounded-lg border border-border bg-bg-secondary p-6">
            <h2 className="mb-3 text-lg font-semibold text-text-primary">
              Active Campaign
            </h2>
            <dl className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <dt className="text-text-muted">Company</dt>
                <dd className="mt-0.5 text-text-primary">
                  {activeTarget.company_name}
                </dd>
              </div>
              <div>
                <dt className="text-text-muted">Domain</dt>
                <dd className="mt-0.5 text-text-primary">
                  {activeTarget.base_domain}
                </dd>
              </div>
            </dl>
          </div>
        </>
      )}
    </div>
  );
}
```

**Step 3: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 4: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/components/campaign/CampaignPicker.tsx dashboard/src/app/page.tsx
git commit -m "feat(dashboard): add CampaignPicker with state recovery on home page"
```

---

## Task 11: StatusBar — Campaign Switcher

**Files:**
- Modify: `dashboard/src/components/layout/StatusBar.tsx`

**Step 1: Add campaign switcher dropdown**

Replace `dashboard/src/components/layout/StatusBar.tsx` entirely:

```typescript
"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { Activity, ChevronDown, Wifi, WifiOff } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import AlertDropdown from "@/components/layout/AlertDropdown";
import type { Target } from "@/types/schema";

export default function StatusBar() {
  const router = useRouter();
  const { connected, activeTarget, currentPhase, setActiveTarget } =
    useCampaignStore();
  const [open, setOpen] = useState(false);
  const [targets, setTargets] = useState<Target[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  // Fetch targets when dropdown opens
  useEffect(() => {
    if (!open) return;
    api
      .getTargets()
      .then((res) => setTargets(res.targets))
      .catch(() => {});
  }, [open]);

  function switchCampaign(target: Target) {
    setActiveTarget(target);
    setOpen(false);
    router.push("/campaign/c2");
  }

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border bg-bg-secondary px-6">
      {/* Left — active campaign info */}
      <div className="flex items-center gap-4">
        {activeTarget ? (
          <div ref={ref} className="relative">
            <button
              onClick={() => setOpen(!open)}
              className="flex items-center gap-2 rounded-md px-2 py-1 transition-colors hover:bg-bg-surface"
            >
              <span className="text-sm text-text-secondary">Campaign:</span>
              <span className="text-sm font-medium text-text-primary">
                {activeTarget.base_domain}
              </span>
              <ChevronDown className="h-3.5 w-3.5 text-text-muted" />
            </button>
            {open && (
              <div className="absolute left-0 top-full mt-1 w-64 rounded-lg border border-border bg-bg-secondary shadow-lg">
                {targets.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => switchCampaign(t)}
                    className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors hover:bg-bg-surface ${
                      t.id === activeTarget.id
                        ? "text-accent"
                        : "text-text-primary"
                    }`}
                  >
                    <span className="truncate">{t.base_domain}</span>
                    <span className="ml-auto text-xs text-text-muted">
                      {t.company_name}
                    </span>
                  </button>
                ))}
              </div>
            )}
            {currentPhase && (
              <span className="ml-2 rounded bg-bg-surface px-2 py-0.5 text-xs text-accent">
                {currentPhase}
              </span>
            )}
          </div>
        ) : (
          <span className="text-sm text-text-muted">No active campaign</span>
        )}
      </div>

      {/* Right — alerts + connection indicator */}
      <div className="flex items-center gap-3">
        <AlertDropdown />
        <div className="flex items-center gap-1.5">
          {connected ? (
            <>
              <Wifi className="h-3.5 w-3.5 text-success" />
              <span className="text-xs text-success">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-danger" />
              <span className="text-xs text-danger">Disconnected</span>
            </>
          )}
        </div>
        <Activity className="h-4 w-4 animate-pulse text-accent" />
      </div>
    </header>
  );
}
```

**Step 2: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/components/layout/StatusBar.tsx
git commit -m "feat(dashboard): add campaign switcher dropdown to StatusBar"
```

---

## Task 12: C2 Page — AssetTree API Hydration + SSE Merge

**Files:**
- Modify: `dashboard/src/app/campaign/c2/page.tsx:37-53` (tree building)
- Modify: `dashboard/src/components/c2/AssetTree.tsx` (add highlight for new nodes)

**Step 1: Rewrite tree building logic in C2 page**

Replace `dashboard/src/app/campaign/c2/page.tsx` entirely:

```typescript
"use client";

import { useEffect, useState, useCallback } from "react";
import { Activity, Settings } from "lucide-react";
import AssetTree, { type TreeNode } from "@/components/c2/AssetTree";
import WorkerConsole from "@/components/c2/WorkerConsole";
import WorkerFeed from "@/components/c2/WorkerFeed";
import StatusBoard from "@/components/c2/StatusBoard";
import SettingsDrawer from "@/components/c2/SettingsDrawer";
import { useEventStream } from "@/hooks/useEventStream";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import type { JobState } from "@/types/schema";
import type { NewAssetEvent } from "@/types/events";

/** Build a hierarchical TreeNode array from flat asset + location data. */
function buildTree(
  baseDomain: string,
  assets: {
    id: number;
    asset_type: string;
    asset_value: string;
    source_tool: string | null;
    locations: { id: number; port: number; protocol: string | null; service: string | null; state: string | null }[];
  }[],
): TreeNode[] {
  const root: TreeNode = {
    id: "root",
    label: baseDomain,
    type: "domain",
    children: [],
  };

  for (const asset of assets) {
    const node: TreeNode = {
      id: `asset-${asset.id}`,
      label: asset.asset_value,
      type: (asset.asset_type === "subdomain" || asset.asset_type === "ip"
        ? asset.asset_type
        : "subdomain") as TreeNode["type"],
      children: asset.locations.map((loc) => ({
        id: `loc-${loc.id}`,
        label: `${loc.port}/${loc.protocol ?? "tcp"}`,
        type: "port" as const,
        meta: { service: loc.service },
      })),
    };
    root.children!.push(node);
  }

  return [root];
}

export default function C2Page() {
  const { activeTarget } = useCampaignStore();
  const { events } = useEventStream(activeTarget?.id ?? null);
  const [jobs, setJobs] = useState<JobState[]>([]);
  const [treeRoots, setTreeRoots] = useState<TreeNode[]>([]);
  const [settingsOpen, setSettingsOpen] = useState(false);

  // Fetch job states periodically
  useEffect(() => {
    if (!activeTarget) return;
    let cancelled = false;

    async function poll() {
      try {
        const res = await api.getStatus(activeTarget!.id);
        if (!cancelled) setJobs(res.jobs);
      } catch {
        /* noop */
      }
    }

    poll();
    const interval = setInterval(poll, 10_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeTarget]);

  // Hydrate tree from API on mount
  useEffect(() => {
    if (!activeTarget) return;
    api
      .getAssets(activeTarget.id)
      .then((res) => {
        setTreeRoots(buildTree(activeTarget.base_domain, res.assets));
      })
      .catch(() => {});
  }, [activeTarget]);

  // Merge SSE NEW_ASSET events into tree
  const lastMergedRef = useCallback(() => {
    let lastIdx = 0;
    return (evts: typeof events) => {
      if (!activeTarget || evts.length === 0) return;
      const newEvents = evts.slice(lastIdx);
      lastIdx = evts.length;

      const assetEvents = newEvents.filter(
        (e) => e.event === "NEW_ASSET",
      ) as NewAssetEvent[];
      if (assetEvents.length === 0) return;

      setTreeRoots((prev) => {
        if (prev.length === 0) return prev;
        const root = { ...prev[0], children: [...(prev[0].children ?? [])] };
        for (const evt of assetEvents) {
          const id = `sse-${evt.asset_value}-${Date.now()}`;
          root.children!.push({
            id,
            label: evt.asset_value,
            type: (evt.asset_type === "subdomain" || evt.asset_type === "ip"
              ? evt.asset_type
              : "subdomain") as TreeNode["type"],
          });
        }
        return [root];
      });
    };
  }, [activeTarget]);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const mergeEvents = useCallback(lastMergedRef(), [lastMergedRef]);

  useEffect(() => {
    mergeEvents(events);
  }, [events, mergeEvents]);

  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">
          No active campaign. Launch one from the{" "}
          <a href="/campaign" className="text-accent underline">
            Campaign
          </a>{" "}
          page.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Activity className="h-5 w-5 text-accent" />
        <h1 className="text-2xl font-bold text-text-primary">C2 Console</h1>
        <span className="rounded bg-bg-surface px-2 py-0.5 text-xs text-accent">
          {activeTarget.base_domain}
        </span>
        <button
          onClick={() => setSettingsOpen(true)}
          className="ml-auto rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface hover:text-text-primary"
          title="Settings"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>

      {/* Phase progress bar */}
      <PhaseProgress currentPhase={jobs[0]?.current_phase ?? null} />

      {/* Status Board */}
      <StatusBoard jobs={jobs} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left — Asset tree */}
        <div className="lg:col-span-1">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <h2 className="mb-3 text-sm font-semibold text-text-secondary">
              Asset Tree
            </h2>
            <AssetTree roots={treeRoots} />
          </div>
        </div>

        {/* Right — Workers + Feed */}
        <div className="space-y-4 lg:col-span-2">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <h2 className="mb-3 text-sm font-semibold text-text-secondary">
              Worker Management
            </h2>
            <WorkerConsole jobs={jobs} />
          </div>

          <WorkerFeed events={events} />
        </div>
      </div>

      {/* Settings Drawer */}
      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        targetId={activeTarget.id}
        currentProfile={activeTarget.target_profile}
      />
    </div>
  );
}

/* ---- Phase progress bar ---- */

const PHASES = ["RECON", "VULN", "EXPLOIT"] as const;

function PhaseProgress({ currentPhase }: { currentPhase: string | null }) {
  const activeIdx = currentPhase
    ? PHASES.findIndex((p) => currentPhase.toUpperCase().includes(p))
    : 0;

  return (
    <div className="flex items-center gap-2">
      {PHASES.map((phase, i) => (
        <div key={phase} className="flex items-center gap-2">
          {i > 0 && (
            <div
              className={`h-px w-6 ${i <= activeIdx ? "bg-accent" : "bg-border"}`}
            />
          )}
          <span
            className={`rounded-full px-3 py-1 text-xs font-medium ${
              i < activeIdx
                ? "bg-success/20 text-success"
                : i === activeIdx
                  ? "bg-accent/20 text-accent"
                  : "bg-bg-surface text-text-muted"
            }`}
          >
            {phase}
          </span>
        </div>
      ))}
    </div>
  );
}
```

**Step 2: Verify TypeScript compiles** (will fail until StatusBoard and SettingsDrawer exist — that's expected, those are in the next tasks)

**Step 3: Commit** (defer commit until Task 13 and 14 are done)

---

## Task 13: StatusBoard Component

**Files:**
- Create: `dashboard/src/components/c2/StatusBoard.tsx`

**Step 1: Create StatusBoard**

Create `dashboard/src/components/c2/StatusBoard.tsx`:

```typescript
"use client";

import { Cpu } from "lucide-react";
import type { JobState } from "@/types/schema";

export default function StatusBoard({ jobs }: { jobs: JobState[] }) {
  const running = jobs.filter((j) => j.status === "RUNNING");

  if (running.length === 0) return null;

  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
      {running.map((job) => (
        <div
          key={job.id}
          className="flex items-center gap-3 rounded-md border border-border bg-bg-secondary px-3 py-2"
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
          </span>
          <Cpu className="h-3.5 w-3.5 text-text-muted" />
          <div className="min-w-0">
            <p className="truncate text-xs font-medium text-text-primary">
              {job.container_name}
            </p>
            <p className="text-[10px] text-text-muted">
              {job.current_phase ?? "—"}
              {job.last_tool_executed && (
                <span className="ml-1 rounded bg-accent/10 px-1 text-accent">
                  {job.last_tool_executed}
                </span>
              )}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
```

**Step 2: Commit** (defer to after Task 14)

---

## Task 14: Settings Drawer Component

**Files:**
- Create: `dashboard/src/components/c2/SettingsDrawer.tsx`

**Step 1: Create SettingsDrawer**

Create `dashboard/src/components/c2/SettingsDrawer.tsx`:

```typescript
"use client";

import { useState } from "react";
import { X, Plus, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { TargetProfile } from "@/types/schema";

interface Props {
  open: boolean;
  onClose: () => void;
  targetId: number;
  currentProfile: TargetProfile | null;
}

export default function SettingsDrawer({
  open,
  onClose,
  targetId,
  currentProfile,
}: Props) {
  const setActiveTarget = useCampaignStore((s) => s.setActiveTarget);
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  const initialHeaders = Object.entries(
    currentProfile?.custom_headers ?? {},
  ).map(([k, v]) => ({ key: k, value: v }));
  const [headers, setHeaders] = useState(
    initialHeaders.length > 0 ? initialHeaders : [{ key: "", value: "" }],
  );
  const [pps, setPps] = useState(
    String(currentProfile?.rate_limits?.pps ?? ""),
  );
  const [saving, setSaving] = useState(false);

  function addHeader() {
    setHeaders([...headers, { key: "", value: "" }]);
  }

  function removeHeader(idx: number) {
    setHeaders(headers.filter((_, i) => i !== idx));
  }

  function updateHeader(idx: number, field: "key" | "value", val: string) {
    setHeaders(headers.map((h, i) => (i === idx ? { ...h, [field]: val } : h)));
  }

  async function handleSave() {
    setSaving(true);
    try {
      const custom_headers: Record<string, string> = {};
      for (const h of headers) {
        if (h.key.trim()) custom_headers[h.key.trim()] = h.value;
      }
      const rate_limits: Record<string, number> = {};
      if (pps) rate_limits.pps = Number(pps);

      const res = await api.updateTargetProfile(targetId, {
        custom_headers,
        rate_limits,
      });

      // Update the store with the new profile
      if (activeTarget) {
        setActiveTarget({
          ...activeTarget,
          target_profile: res.target_profile,
        });
      }
      onClose();
    } catch {
      // error handled by API client
    } finally {
      setSaving(false);
    }
  }

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/50"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed inset-y-0 right-0 z-50 w-96 border-l border-border bg-bg-secondary shadow-lg">
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <span className="text-sm font-semibold text-text-primary">
            Campaign Settings
          </span>
          <button
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:bg-bg-surface hover:text-text-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-6 overflow-y-auto p-4">
          {/* Custom Headers */}
          <div className="space-y-2">
            <label className="text-xs font-medium text-text-secondary">
              Custom Headers
            </label>
            {headers.map((h, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  value={h.key}
                  onChange={(e) => updateHeader(i, "key", e.target.value)}
                  placeholder="Header name"
                  className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                />
                <input
                  value={h.value}
                  onChange={(e) => updateHeader(i, "value", e.target.value)}
                  placeholder="Value"
                  className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                />
                <button
                  onClick={() => removeHeader(i)}
                  className="rounded p-1 text-text-muted hover:text-danger"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
            <button
              onClick={addHeader}
              className="flex items-center gap-1 text-xs text-accent hover:underline"
            >
              <Plus className="h-3 w-3" /> Add header
            </button>
          </div>

          {/* PPS Rate Limit */}
          <div className="space-y-2">
            <label className="text-xs font-medium text-text-secondary">
              Rate Limit (Packets Per Second)
            </label>
            <input
              type="number"
              value={pps}
              onChange={(e) => setPps(e.target.value)}
              placeholder="e.g. 50"
              className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
          </div>

          {/* Save */}
          <button
            onClick={handleSave}
            disabled={saving}
            className="w-full rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>
        </div>
      </div>
    </>
  );
}
```

**Step 2: Verify TypeScript compiles (all C2 components now exist)**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit Tasks 12-14 together**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/app/campaign/c2/page.tsx dashboard/src/components/c2/StatusBoard.tsx dashboard/src/components/c2/SettingsDrawer.tsx
git commit -m "feat(dashboard): add StatusBoard, SettingsDrawer, API-hydrated AssetTree to C2"
```

---

## Task 15: Wire Assets Page to API

**Files:**
- Modify: `dashboard/src/app/campaign/assets/page.tsx`

**Step 1: Replace placeholder with API call**

Replace `dashboard/src/app/campaign/assets/page.tsx` entirely:

```typescript
"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Asset } from "@/types/schema";

const columns: ColumnDef<Asset, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  {
    accessorKey: "asset_type",
    header: "Type",
    cell: ({ getValue }) => {
      const v = getValue() as string;
      return (
        <span className="rounded bg-accent/10 px-2 py-0.5 text-xs text-accent">
          {v}
        </span>
      );
    },
  },
  { accessorKey: "asset_value", header: "Value" },
  { accessorKey: "source_tool", header: "Source" },
  {
    accessorKey: "created_at",
    header: "Discovered",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

export default function AssetsPage() {
  const router = useRouter();
  const { activeTarget } = useCampaignStore();
  const [data, setData] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    api
      .getAssets(activeTarget.id)
      .then((res) => setData(res.assets))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [activeTarget, router]);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Assets</h1>
      <p className="text-sm text-text-secondary">
        Discovered subdomains, IPs, and CIDRs
      </p>
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-accent" />
        </div>
      ) : (
        <DataTable data={data} columns={columns} />
      )}
    </div>
  );
}
```

**Step 2: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/app/campaign/assets/page.tsx
git commit -m "feat(dashboard): wire Assets page to GET /assets API"
```

---

## Task 16: Wire Cloud Page to API

**Files:**
- Modify: `dashboard/src/app/campaign/cloud/page.tsx`

**Step 1: Replace placeholder with API call**

Replace `dashboard/src/app/campaign/cloud/page.tsx` entirely:

```typescript
"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { CloudAsset, CloudProvider } from "@/types/schema";

const PROVIDER_COLORS: Record<CloudProvider, string> = {
  AWS: "bg-warning/20 text-warning",
  Azure: "bg-accent/20 text-accent",
  GCP: "bg-danger/20 text-danger",
  Other: "bg-bg-surface text-text-muted",
};

const columns: ColumnDef<CloudAsset, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  {
    accessorKey: "provider",
    header: "Provider",
    cell: ({ getValue }) => {
      const p = getValue() as CloudProvider;
      return (
        <span
          className={`rounded px-2 py-0.5 text-xs font-medium ${PROVIDER_COLORS[p] ?? PROVIDER_COLORS.Other}`}
        >
          {p}
        </span>
      );
    },
  },
  { accessorKey: "asset_type", header: "Type" },
  {
    accessorKey: "url",
    header: "URL",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? (
        <span className="inline-block max-w-xs truncate" title={v}>
          {v}
        </span>
      ) : (
        "—"
      );
    },
  },
  {
    accessorKey: "is_public",
    header: "Public",
    cell: ({ getValue }) =>
      getValue() ? (
        <span className="font-medium text-danger">Yes</span>
      ) : (
        <span className="text-success">No</span>
      ),
  },
  {
    accessorKey: "created_at",
    header: "Found",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

export default function CloudPage() {
  const router = useRouter();
  const { activeTarget } = useCampaignStore();
  const [data, setData] = useState<CloudAsset[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    api
      .getCloudAssets(activeTarget.id)
      .then((res) => setData(res.cloud_assets))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [activeTarget, router]);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Cloud Assets</h1>
      <p className="text-sm text-text-secondary">
        AWS, Azure, and GCP resource findings
      </p>
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-accent" />
        </div>
      ) : (
        <DataTable data={data} columns={columns} />
      )}
    </div>
  );
}
```

**Step 2: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/app/campaign/cloud/page.tsx
git commit -m "feat(dashboard): wire Cloud page to GET /cloud_assets API"
```

---

## Task 17: Wire Vulns Page to API with Severity Tabs

**Files:**
- Modify: `dashboard/src/app/campaign/vulns/page.tsx`

**Step 1: Replace placeholder with API call and add severity filter tabs**

Replace `dashboard/src/app/campaign/vulns/page.tsx` entirely:

```typescript
"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { VulnSeverity } from "@/types/schema";

interface VulnRow {
  id: number;
  target_id: number;
  asset_id: number | null;
  asset_value: string | null;
  severity: VulnSeverity;
  title: string;
  description: string | null;
  poc: string | null;
  source_tool: string | null;
  created_at: string | null;
  updated_at: string | null;
}

const SEV_COLORS: Record<VulnSeverity, string> = {
  critical: "bg-critical/20 text-critical",
  high: "bg-danger/20 text-danger",
  medium: "bg-warning/20 text-warning",
  low: "bg-info/20 text-info",
  info: "bg-bg-surface text-text-muted",
};

const columns: ColumnDef<VulnRow, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ getValue }) => {
      const s = getValue() as VulnSeverity;
      return (
        <span
          className={`rounded px-2 py-0.5 text-xs font-medium ${SEV_COLORS[s] ?? ""}`}
        >
          {s.toUpperCase()}
        </span>
      );
    },
  },
  { accessorKey: "title", header: "Title" },
  { accessorKey: "asset_value", header: "Asset" },
  { accessorKey: "source_tool", header: "Source" },
  {
    accessorKey: "created_at",
    header: "Found",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

const TABS = ["all", "critical", "high", "medium", "low", "info"] as const;

export default function VulnsPage() {
  const router = useRouter();
  const { activeTarget } = useCampaignStore();
  const [data, setData] = useState<VulnRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<(typeof TABS)[number]>("all");
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    setLoading(true);
    const severity = tab === "all" ? undefined : tab;
    api
      .getVulnerabilities(activeTarget.id, severity)
      .then((res) => setData(res.vulnerabilities as VulnRow[]))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [activeTarget, tab, router]);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Vulnerabilities</h1>
      <p className="text-sm text-text-secondary">
        Findings grouped by severity
      </p>

      {/* Severity tabs */}
      <div className="flex gap-1">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
              tab === t
                ? "bg-accent/20 text-accent"
                : "text-text-muted hover:bg-bg-surface hover:text-text-primary"
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-accent" />
        </div>
      ) : (
        <>
          <DataTable data={data} columns={columns} />

          {/* Expandable detail panel — simple click-to-expand */}
          {expanded !== null && (() => {
            const vuln = data.find((v) => v.id === expanded);
            if (!vuln) return null;
            return (
              <div className="rounded-lg border border-border bg-bg-secondary p-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-text-primary">
                    {vuln.title}
                  </h3>
                  <button
                    onClick={() => setExpanded(null)}
                    className="text-xs text-text-muted hover:text-text-primary"
                  >
                    Close
                  </button>
                </div>
                {vuln.description && (
                  <p className="mt-2 text-xs text-text-secondary">
                    {vuln.description}
                  </p>
                )}
                {vuln.poc && (
                  <pre className="mt-2 overflow-x-auto rounded bg-bg-tertiary p-2 text-xs text-text-primary">
                    {vuln.poc}
                  </pre>
                )}
              </div>
            );
          })()}
        </>
      )}
    </div>
  );
}
```

**Step 2: Verify TypeScript compiles**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add dashboard/src/app/campaign/vulns/page.tsx
git commit -m "feat(dashboard): wire Vulns page to API with severity filter tabs"
```

---

## Task 18: Final Build Verification

**Step 1: Run full orchestrator test suite**

Run: `cd /home/kiddulu/Projects/WebAppBH && python -m pytest tests/test_main.py -v`
Expected: All PASSED

**Step 2: Run dashboard TypeScript check**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Run Next.js build**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx next build`
Expected: Build succeeds

**Step 4: Run ESLint**

Run: `cd /home/kiddulu/Projects/WebAppBH/dashboard && npx eslint src/`
Expected: No errors (or only pre-existing warnings)

**Step 5: If any issues found, fix and commit**

```bash
cd /home/kiddulu/Projects/WebAppBH
git add -A
git commit -m "fix: address build/lint issues from Phase 3 implementation"
```
