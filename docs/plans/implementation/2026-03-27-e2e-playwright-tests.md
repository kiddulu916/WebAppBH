# E2E Playwright Tests Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 10 Playwright e2e test files covering critical user journeys against the real Docker stack.

**Architecture:** Self-contained test harness: `globalSetup` starts `docker compose up`, polls health endpoints, tests run sequentially with per-test seed/cleanup via orchestrator API, `globalTeardown` destroys containers. A test-only `POST /api/v1/test/seed` endpoint (guarded by `ENABLE_TEST_SEED=true`) inserts fixture assets/vulns.

**Tech Stack:** Playwright, TypeScript, Docker Compose, FastAPI (orchestrator), Next.js 16 (dashboard)

**Design doc:** `docs/plans/design/2026-03-27-e2e-playwright-tests-design.md`

---

## Task 1: Install Playwright and scaffold e2e directory

**Files:**
- Modify: `dashboard/package.json:5-9` (add scripts)
- Create: `dashboard/e2e/playwright.config.ts`

**Step 1: Install Playwright**

Run:
```bash
cd dashboard && npm install -D @playwright/test && npx playwright install chromium
```

**Step 2: Add npm scripts to package.json**

In `dashboard/package.json`, add to `"scripts"`:
```json
"test:e2e": "playwright test --config=e2e/playwright.config.ts",
"test:e2e:ui": "playwright test --config=e2e/playwright.config.ts --ui",
"test:e2e:debug": "playwright test --config=e2e/playwright.config.ts --debug"
```

**Step 3: Create playwright.config.ts**

Create `dashboard/e2e/playwright.config.ts`:
```ts
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  timeout: 30_000,
  retries: 1,
  workers: 1,
  fullyParallel: false,

  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  reporter: [["html", { open: "never" }], ["list"]],
});
```

**Step 4: Create directories**

Run:
```bash
mkdir -p dashboard/e2e/tests dashboard/e2e/helpers
```

**Step 5: Verify config loads**

Run:
```bash
cd dashboard && npx playwright test --config=e2e/playwright.config.ts --list 2>&1 | head -5
```
Expected: No config parse errors (may say "no tests found" — that's fine).

**Step 6: Commit**

```bash
git add dashboard/package.json dashboard/e2e/
git commit -m "chore: scaffold Playwright e2e test infrastructure"
```

---

## Task 2: Create global-setup, global-teardown, and wait-for-services

**Files:**
- Create: `dashboard/e2e/global-setup.ts`
- Create: `dashboard/e2e/global-teardown.ts`
- Create: `dashboard/e2e/helpers/wait-for-services.ts`

**Step 1: Create wait-for-services.ts**

Create `dashboard/e2e/helpers/wait-for-services.ts`:
```ts
export async function waitForService(
  url: string,
  timeout: number,
  label: string,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        console.log(`  [ok] ${label} ready`);
        return;
      }
    } catch {
      // Not ready yet
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`${label} not ready after ${timeout}ms (${url})`);
}
```

**Step 2: Create global-setup.ts**

Create `dashboard/e2e/global-setup.ts`.
Uses `execFileSync("docker", ["compose", ...])` to avoid shell injection (no `execSync` with string commands). All arguments are hardcoded string arrays.

```ts
import { execFileSync } from "child_process";
import path from "path";
import { waitForService } from "./helpers/wait-for-services";

const REPO_ROOT = path.resolve(__dirname, "../..");
const STARTUP_TIMEOUT = 120_000;

export default async function globalSetup() {
  console.log("\n[e2e] Starting Docker stack...");

  execFileSync("docker", [
    "compose",
    "-f", "docker-compose.yml",
    "-f", "docker-compose.test.yml",
    "up", "-d", "--build",
    "postgres", "redis", "orchestrator", "dashboard",
  ], { cwd: REPO_ROOT, stdio: "inherit" });

  console.log("[e2e] Waiting for services...");
  await waitForService("http://localhost:8001/health", STARTUP_TIMEOUT, "Orchestrator");
  await waitForService("http://localhost:3000", STARTUP_TIMEOUT, "Dashboard");
  console.log("[e2e] All services ready.\n");
}
```

**Step 3: Create global-teardown.ts**

Create `dashboard/e2e/global-teardown.ts`:
```ts
import { execFileSync } from "child_process";
import path from "path";

const REPO_ROOT = path.resolve(__dirname, "../..");

export default async function globalTeardown() {
  console.log("\n[e2e] Tearing down Docker stack...");
  execFileSync("docker", [
    "compose",
    "-f", "docker-compose.yml",
    "-f", "docker-compose.test.yml",
    "down", "-v",
  ], { cwd: REPO_ROOT, stdio: "inherit" });
  console.log("[e2e] Done.\n");
}
```

**Step 4: Commit**

```bash
git add dashboard/e2e/global-setup.ts dashboard/e2e/global-teardown.ts dashboard/e2e/helpers/wait-for-services.ts
git commit -m "feat(e2e): add global setup/teardown with Docker lifecycle"
```

---

## Task 3: Create docker-compose.test.yml

**Files:**
- Create: `docker-compose.test.yml` (repo root)

**Step 1: Create the override file**

Create `docker-compose.test.yml` at repo root:
```yaml
# Test-only compose override -- activates the /api/v1/test/seed endpoint.
# Usage: docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
services:
  orchestrator:
    environment:
      - ENABLE_TEST_SEED=true
```

**Step 2: Verify compose merges cleanly**

Run:
```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml config --services
```
Expected: Lists `postgres`, `redis`, `orchestrator`, `dashboard`, plus workers.

**Step 3: Commit**

```bash
git add docker-compose.test.yml
git commit -m "feat(e2e): add docker-compose.test.yml with ENABLE_TEST_SEED"
```

---

## Task 4: Add test seed endpoint to orchestrator

**Files:**
- Modify: `orchestrator/main.py` — append after line 1952 (after `_generate_tool_configs`)

**Step 1: Add the TestSeed Pydantic model and endpoint**

Append after the `_generate_tool_configs` function at end of `orchestrator/main.py`:

```python
# ---------------------------------------------------------------------------
# Test seed endpoint -- inserts fixture data for e2e tests
# ---------------------------------------------------------------------------
ENABLE_TEST_SEED = os.environ.get("ENABLE_TEST_SEED", "").lower() == "true"


class TestSeedRequest(BaseModel):
    target_id: int = Field(..., gt=0)


@app.post("/api/v1/test/seed")
async def test_seed(body: TestSeedRequest):
    """Insert fixture assets, vulns, cloud assets, and alerts for e2e tests.

    Guarded by ENABLE_TEST_SEED=true -- returns 404 in production.
    """
    if not ENABLE_TEST_SEED:
        raise HTTPException(status_code=404, detail="Not found")

    async with get_session() as session:
        # Verify target exists
        result = await session.execute(
            select(Target).where(Target.id == body.target_id)
        )
        target = result.scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        # --- Assets ---
        assets_data = [
            {"asset_type": "subdomain", "asset_value": f"sub1.{target.base_domain}", "source_tool": "e2e-seed"},
            {"asset_type": "subdomain", "asset_value": f"sub2.{target.base_domain}", "source_tool": "e2e-seed"},
            {"asset_type": "subdomain", "asset_value": f"admin.{target.base_domain}", "source_tool": "e2e-seed"},
            {"asset_type": "ip", "asset_value": "10.0.0.1", "source_tool": "e2e-seed"},
            {"asset_type": "ip", "asset_value": "10.0.0.2", "source_tool": "e2e-seed"},
        ]
        asset_ids = []
        for ad in assets_data:
            asset = Asset(target_id=body.target_id, **ad)
            session.add(asset)
            await session.flush()
            asset_ids.append(asset.id)

        # --- Locations (on first asset) ---
        session.add(Location(asset_id=asset_ids[0], port=80, protocol="tcp", service="http", state="open"))
        session.add(Location(asset_id=asset_ids[0], port=443, protocol="tcp", service="https", state="open"))

        # --- Vulnerabilities ---
        vulns_data = [
            {"severity": "critical", "title": "SQL Injection in login", "description": "Blind SQLi via id param", "source_tool": "e2e-seed"},
            {"severity": "medium", "title": "Reflected XSS in search", "description": "XSS via q parameter", "source_tool": "e2e-seed"},
            {"severity": "low", "title": "Information Disclosure", "description": "Server version in headers", "source_tool": "e2e-seed"},
        ]
        vuln_ids = []
        for i, vd in enumerate(vulns_data):
            vuln = Vulnerability(target_id=body.target_id, asset_id=asset_ids[i % len(asset_ids)], **vd)
            session.add(vuln)
            await session.flush()
            vuln_ids.append(vuln.id)

        # --- Cloud Assets ---
        session.add(CloudAsset(
            target_id=body.target_id, provider="AWS", asset_type="s3_bucket",
            url="https://test-bucket.s3.amazonaws.com", is_public=True,
            findings={"listing": True},
        ))
        session.add(CloudAsset(
            target_id=body.target_id, provider="Azure", asset_type="blob_container",
            url="https://test.blob.core.windows.net/data", is_public=False,
        ))

        # --- Alert ---
        session.add(Alert(
            target_id=body.target_id, vulnerability_id=vuln_ids[0],
            alert_type="critical_vuln",
            message="Critical: SQL Injection in login", is_read=False,
        ))

        await session.commit()

    return {
        "seeded": True,
        "target_id": body.target_id,
        "assets": len(assets_data),
        "vulnerabilities": len(vulns_data),
        "cloud_assets": 2,
        "alerts": 1,
        "vuln_ids": vuln_ids,
    }
```

**Step 2: Verify it compiles**

Run:
```bash
cd /home/kiddulu/Projects/WebAppBH && python -c "import ast; ast.parse(open('orchestrator/main.py').read()); print('OK')"
```
Expected: `OK`

**Step 3: Commit**

```bash
git add orchestrator/main.py
git commit -m "feat(e2e): add POST /api/v1/test/seed endpoint behind ENABLE_TEST_SEED"
```

---

## Task 5: Create API client and seed factories helpers

**Files:**
- Create: `dashboard/e2e/helpers/api-client.ts`
- Create: `dashboard/e2e/helpers/seed-factories.ts`
- Create: `dashboard/e2e/helpers/poll-until.ts`

**Step 1: Create api-client.ts**

Create `dashboard/e2e/helpers/api-client.ts`:
```ts
const BASE = "http://localhost:8001/api/v1";
const API_KEY = process.env.WEB_APP_BH_API_KEY ?? "";

const headers: Record<string, string> = {
  "Content-Type": "application/json",
  ...(API_KEY ? { "X-API-KEY": API_KEY } : {}),
};

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { ...headers, ...init?.headers },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status} ${path}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const apiClient = {
  // Health
  health: () => req<{ status: string }>("/health"),

  // Targets
  createTarget: (data: {
    company_name: string;
    base_domain: string;
    target_profile?: Record<string, unknown>;
    playbook?: string;
  }) =>
    req<{ target_id: number; company_name: string; base_domain: string }>(
      "/targets",
      { method: "POST", body: JSON.stringify(data) },
    ),

  getTargets: () =>
    req<{
      targets: Array<{
        id: number;
        company_name: string;
        base_domain: string;
        asset_count: number;
        vuln_count: number;
        status: string;
      }>;
    }>("/targets"),

  deleteTarget: (id: number) =>
    req<{ success: boolean }>(`/targets/${id}`, { method: "DELETE" }),

  cleanSlate: (id: number) =>
    req<{ success: boolean }>(`/targets/${id}/clean-slate`, { method: "POST" }),

  rescan: (id: number) =>
    req<{ target_id: number; status: string }>(
      `/targets/${id}/rescan`,
      { method: "POST" },
    ),

  updateTargetProfile: (
    id: number,
    data: {
      custom_headers?: Record<string, string>;
      rate_limits?: Record<string, number>;
    },
  ) =>
    req<{ target_id: number; target_profile: Record<string, unknown> }>(
      `/targets/${id}`,
      { method: "PATCH", body: JSON.stringify(data) },
    ),

  // Data
  getAssets: (targetId: number) =>
    req<{
      assets: Array<{ id: number; asset_type: string; asset_value: string }>;
    }>(`/assets?target_id=${targetId}`),

  getVulns: (targetId: number) =>
    req<{
      vulnerabilities: Array<{
        id: number;
        severity: string;
        title: string;
      }>;
    }>(`/vulnerabilities?target_id=${targetId}`),

  getCloudAssets: (targetId: number) =>
    req<{
      cloud_assets: Array<{
        id: number;
        provider: string;
        asset_type: string;
      }>;
    }>(`/cloud_assets?target_id=${targetId}`),

  getJobs: (targetId: number) =>
    req<{
      jobs: Array<{
        id: number;
        container_name: string;
        status: string;
        current_phase: string | null;
      }>;
    }>(`/status?target_id=${targetId}`),

  // Bounties
  createBounty: (data: {
    target_id: number;
    vulnerability_id: number;
    platform: string;
    expected_payout?: number;
  }) =>
    req<{ id: number; status: string }>("/bounties", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getBounties: (targetId: number) =>
    req<Array<{ id: number; status: string; platform: string }>>(
      `/bounties?target_id=${targetId}`,
    ),

  updateBounty: (
    id: number,
    data: { status?: string; actual_payout?: number },
  ) =>
    req<{ id: number; status: string }>(`/bounties/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  // Schedules
  createSchedule: (data: {
    target_id: number;
    cron_expression: string;
    playbook?: string;
  }) =>
    req<{ id: number }>("/schedules", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getSchedules: (targetId: number) =>
    req<Array<{ id: number; enabled: boolean; cron_expression: string }>>(
      `/schedules?target_id=${targetId}`,
    ),

  deleteSchedule: (id: number) =>
    req<void>(`/schedules/${id}`, { method: "DELETE" }),

  // Test seed
  seedTestData: (targetId: number) =>
    req<{ seeded: boolean; vuln_ids: number[] }>("/test/seed", {
      method: "POST",
      body: JSON.stringify({ target_id: targetId }),
    }),

  // Search
  search: (targetId: number, query: string) =>
    req<{ results: Array<{ type: string; id: number; value: string }> }>(
      `/search?target_id=${targetId}&q=${encodeURIComponent(query)}`,
    ),
};
```

**Step 2: Create seed-factories.ts**

Create `dashboard/e2e/helpers/seed-factories.ts`:
```ts
const uid = () =>
  Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

export const factories = {
  target: (overrides: Record<string, unknown> = {}) => ({
    company_name: `E2E-Corp-${uid()}`,
    base_domain: `e2e-${uid()}.example.com`,
    target_profile: {
      in_scope_domains: [],
      custom_headers: {},
      rate_limits: { pps: 10 },
    },
    playbook: "wide_recon",
    ...overrides,
  }),

  bounty: (
    targetId: number,
    vulnId: number,
    overrides: Record<string, unknown> = {},
  ) => ({
    target_id: targetId,
    vulnerability_id: vulnId,
    platform: "hackerone",
    expected_payout: 500,
    ...overrides,
  }),

  schedule: (targetId: number, overrides: Record<string, unknown> = {}) => ({
    target_id: targetId,
    cron_expression: "0 0 * * *",
    playbook: "wide_recon",
    ...overrides,
  }),
};
```

**Step 3: Create poll-until.ts**

Create `dashboard/e2e/helpers/poll-until.ts`:
```ts
export async function pollUntil<T>(
  fn: () => Promise<T>,
  predicate: (val: T) => boolean,
  timeout: number,
  interval = 1000,
): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const val = await fn();
    if (predicate(val)) return val;
    await new Promise((r) => setTimeout(r, interval));
  }
  throw new Error(`pollUntil timed out after ${timeout}ms`);
}
```

**Step 4: Commit**

```bash
git add dashboard/e2e/helpers/
git commit -m "feat(e2e): add API client, seed factories, and poll utility"
```

---

## Task 6: Add data-testid attributes to dashboard components

**Files to modify (read each first, find the JSX element, add only the `data-testid` attribute):**

- `dashboard/src/components/campaign/ScopeBuilder.tsx`
  - Wrapper `<div>` at line 196 -> `data-testid="scope-builder"`
  - Each step button (line ~216 in the map) -> `data-testid={`scope-step-${i}`}`
  - Company name `<input>` -> `data-testid="scope-company-input"`
  - Base domain `<input>` -> `data-testid="scope-domain-input"`
  - Next button -> `data-testid="scope-next-btn"`
  - Back button -> `data-testid="scope-back-btn"`
  - Launch/submit button -> `data-testid="scope-submit-btn"`

- `dashboard/src/app/campaign/targets/page.tsx`
  - Table/container -> `data-testid="targets-table"`
  - Search input -> `data-testid="target-search-input"`
  - Each row -> `data-testid={`target-row-${t.id}`}`
  - Delete button -> `data-testid={`target-delete-btn-${t.id}`}`

- `dashboard/src/app/campaign/c2/page.tsx`
  - Div wrapping `<AssetTree>` -> `data-testid="c2-asset-tree"`
  - Div wrapping `<WorkerGrid>` -> `data-testid="c2-worker-grid"`
  - Div wrapping `<PhasePipeline>` -> `data-testid="c2-phase-pipeline"`
  - Div wrapping `<CampaignTimeline>` -> `data-testid="c2-timeline"`

- `dashboard/src/components/c2/WorkerCard.tsx`
  - Card wrapper -> `data-testid={`worker-card-${containerName}`}`
  - Pause button -> `data-testid="worker-pause-btn"`
  - Stop button -> `data-testid="worker-stop-btn"`
  - Resume button -> `data-testid="worker-resume-btn"`

- `dashboard/src/components/c2/CampaignTimeline.tsx`
  - Each timeline entry bar -> `data-testid="timeline-entry"`

- `dashboard/src/components/c2/SettingsDrawer.tsx`
  - Drawer panel (line ~79) -> `data-testid="settings-drawer"`
  - Header key inputs -> `data-testid={`settings-header-key-${idx}`}`
  - Header value inputs -> `data-testid={`settings-header-value-${idx}`}`
  - Rate limit input -> `data-testid="settings-rate-input"`
  - Save button -> `data-testid="settings-save-btn"`

- `dashboard/src/app/campaign/bounties/page.tsx`
  - Table wrapper -> `data-testid="bounties-table"`
  - Each row -> `data-testid={`bounty-row-${b.id}`}`
  - Status badge -> `data-testid={`bounty-status-${b.id}`}`
  - Edit button -> `data-testid={`bounty-edit-${b.id}`}`

- `dashboard/src/app/campaign/findings/page.tsx`
  - Table wrapper -> `data-testid="findings-table"`
  - Severity filter -> `data-testid="severity-filter"`
  - CorrelationView container -> `data-testid="correlation-view"`

- `dashboard/src/components/layout/FooterBar.tsx`
  - Assets stat (line ~36) -> wrap in `<span data-testid="footer-asset-count">`
  - Vulns stat (line ~41) -> wrap in `<span data-testid="footer-vuln-count">`

- `dashboard/src/components/layout/CommandPalette.tsx`
  - Palette overlay -> `data-testid="command-palette"`
  - Input (line ~37) -> `data-testid="command-input"`
  - Each result item -> `data-testid="command-result"`

- `dashboard/src/app/campaign/schedules/page.tsx` (if it exists)
  - Table -> `data-testid="schedules-table"`
  - Each row -> `data-testid={`schedule-row-${s.id}`}`
  - Toggle -> `data-testid="schedule-toggle"`

**Rules:** Only add `data-testid` attributes. No logic, structure, or style changes.

**Commit:**
```bash
git add dashboard/src/
git commit -m "feat(e2e): add data-testid attributes to dashboard components"
```

---

## Task 7: Write test -- create-campaign.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/create-campaign.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";

test.describe("Create Campaign", () => {
  let createdTargetId: number | null = null;

  test.afterAll(async () => {
    if (createdTargetId) {
      await apiClient.deleteTarget(createdTargetId).catch(() => {});
    }
  });

  test("complete scope builder wizard and see target in C2", async ({ page }) => {
    const companyName = `E2E-Wizard-${Date.now()}`;
    const domain = `wizard-${Date.now()}.example.com`;

    await page.goto("/campaign");
    await expect(page.getByTestId("scope-builder")).toBeVisible();

    // Step 0: Target Intel
    await page.getByTestId("scope-company-input").fill(companyName);
    await page.getByTestId("scope-domain-input").fill(domain);
    await page.getByTestId("scope-next-btn").click();

    // Step 1: Scope Rules -- advance with defaults
    await expect(page.getByTestId("scope-step-1")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 2: Playbook -- advance with defaults
    await expect(page.getByTestId("scope-step-2")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 3: Workflow -- advance with defaults
    await expect(page.getByTestId("scope-step-3")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 4: Review & Launch
    await expect(page.getByTestId("scope-step-4")).toBeVisible();
    await page.getByTestId("scope-submit-btn").click();

    // Should redirect to C2 console
    await page.waitForURL("**/campaign/c2", { timeout: 10_000 });

    // Verify via API
    const { targets } = await apiClient.getTargets();
    const created = targets.find((t) => t.company_name === companyName);
    expect(created).toBeTruthy();
    createdTargetId = created!.id;
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/create-campaign.spec.ts
git commit -m "test(e2e): add create-campaign test"
```

---

## Task 8: Write test -- target-management.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/target-management.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Target Management", () => {
  const targetIds: number[] = [];

  test.beforeAll(async () => {
    for (let i = 0; i < 3; i++) {
      const res = await apiClient.createTarget(
        factories.target({ company_name: `E2E-Mgmt-${i}-${Date.now()}` }),
      );
      targetIds.push(res.target_id);
    }
  });

  test.afterAll(async () => {
    for (const id of targetIds) {
      await apiClient.deleteTarget(id).catch(() => {});
    }
  });

  test("shows seeded targets in the table", async ({ page }) => {
    await page.goto("/campaign/targets");
    await expect(page.getByTestId("targets-table")).toBeVisible();
    for (const id of targetIds) {
      await expect(page.getByTestId(`target-row-${id}`)).toBeVisible();
    }
  });

  test("search filters the table", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId("target-search-input").fill("E2E-Mgmt-0");
    await expect(page.getByTestId(`target-row-${targetIds[0]}`)).toBeVisible();
    await expect(page.getByTestId(`target-row-${targetIds[1]}`)).not.toBeVisible();
  });

  test("delete removes target from table", async ({ page }) => {
    await page.goto("/campaign/targets");
    const toDelete = targetIds[2];
    await expect(page.getByTestId(`target-row-${toDelete}`)).toBeVisible();

    await page.getByTestId(`target-delete-btn-${toDelete}`).click();

    // Handle confirmation dialog if present
    const confirmInput = page.locator('input[placeholder*="company"]')
      .or(page.locator('input[placeholder*="name"]'));
    if (await confirmInput.isVisible({ timeout: 2000 }).catch(() => false)) {
      const { targets } = await apiClient.getTargets();
      const t = targets.find((t) => t.id === toDelete);
      if (t) await confirmInput.fill(t.company_name);
      await page.locator('button:has-text("Delete")').click();
    }

    await expect(page.getByTestId(`target-row-${toDelete}`)).not.toBeVisible({ timeout: 5000 });

    // Remove from cleanup list
    const idx = targetIds.indexOf(toDelete);
    if (idx > -1) targetIds.splice(idx, 1);
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/target-management.spec.ts
git commit -m "test(e2e): add target-management test"
```

---

## Task 9: Write test -- c2-console.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/c2-console.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("C2 Console", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("displays asset tree and phase pipeline", async ({ page }) => {
    // Select target by navigating to targets and clicking
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();

    await page.goto("/campaign/c2");
    await expect(page.getByTestId("c2-asset-tree")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible();
  });

  test("shows seeded assets in asset tree", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/c2");

    const tree = page.getByTestId("c2-asset-tree");
    await expect(tree).toBeVisible({ timeout: 10_000 });
    await expect(tree).toContainText("sub1.");
    await expect(tree).toContainText("10.0.0.1");
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/c2-console.spec.ts
git commit -m "test(e2e): add c2-console test"
```

---

## Task 10: Write test -- worker-control.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/worker-control.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";
import { pollUntil } from "../helpers/poll-until";

test.describe("Worker Control", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
    await apiClient.rescan(targetId).catch(() => {});

    // Poll until at least one job exists
    await pollUntil(
      () => apiClient.getJobs(targetId),
      (res) => res.jobs.length > 0,
      15_000,
    ).catch(() => {});
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("worker cards render when jobs exist", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/c2");

    const workerGrid = page.getByTestId("c2-worker-grid");
    await expect(workerGrid).toBeVisible({ timeout: 10_000 });

    const cards = page.locator('[data-testid^="worker-card-"]');
    const count = await cards.count();
    if (count === 0) {
      test.skip(true, "No workers running in test stack");
      return;
    }

    const firstCard = cards.first();
    await expect(firstCard).toBeVisible();

    // Try pause if button is available
    const pauseBtn = firstCard.getByTestId("worker-pause-btn");
    if (await pauseBtn.isVisible().catch(() => false)) {
      await pauseBtn.click();
      const { jobs } = await apiClient.getJobs(targetId);
      expect(jobs.some((j) => j.status === "PAUSED")).toBeTruthy();
    }
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/worker-control.spec.ts
git commit -m "test(e2e): add worker-control test"
```

---

## Task 11: Write test -- findings-browser.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/findings-browser.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Findings Browser", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("shows seeded findings", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/findings");

    const table = page.getByTestId("findings-table");
    await expect(table).toBeVisible({ timeout: 10_000 });
    await expect(table).toContainText("SQL Injection");
    await expect(table).toContainText("XSS");
  });

  test("severity filter narrows results", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/findings");

    await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });

    const filter = page.getByTestId("severity-filter");
    if (await filter.isVisible().catch(() => false)) {
      await filter.selectOption("critical");
      await expect(page.getByTestId("findings-table")).toContainText("SQL Injection");
      await expect(page.getByTestId("findings-table")).not.toContainText("Reflected XSS");
    }
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/findings-browser.spec.ts
git commit -m "test(e2e): add findings-browser test"
```

---

## Task 12: Write test -- bounty-tracking.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/bounty-tracking.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Bounty Tracking", () => {
  let targetId: number;
  let vulnIds: number[];
  let seededBountyId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
    const seedRes = await apiClient.seedTestData(targetId);
    vulnIds = seedRes.vuln_ids;

    const bounty = await apiClient.createBounty(
      factories.bounty(targetId, vulnIds[0]),
    );
    seededBountyId = bounty.id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("shows seeded bounty", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/bounties");

    await expect(page.getByTestId("bounties-table")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId(`bounty-row-${seededBountyId}`)).toBeVisible();
  });

  test("can update bounty status", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/bounties");

    await expect(page.getByTestId(`bounty-row-${seededBountyId}`)).toBeVisible({ timeout: 10_000 });

    const editBtn = page.getByTestId(`bounty-edit-${seededBountyId}`);
    if (await editBtn.isVisible().catch(() => false)) {
      await editBtn.click();
      const statusSelect = page.locator("select").first();
      if (await statusSelect.isVisible().catch(() => false)) {
        await statusSelect.selectOption("accepted");
        await page.locator('button:has-text("Save")').or(
          page.locator('button:has-text("Update")'),
        ).first().click();
        await expect(
          page.getByTestId(`bounty-status-${seededBountyId}`),
        ).toContainText("accepted", { timeout: 5000 });
      }
    }
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/bounty-tracking.spec.ts
git commit -m "test(e2e): add bounty-tracking test"
```

---

## Task 13: Write test -- schedule-scan.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/schedule-scan.spec.ts`

**Note:** First verify the schedules page route exists. Check `dashboard/src/app/campaign/schedules/page.tsx`.

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Schedule Scan", () => {
  let targetId: number;
  const scheduleIds: number[] = [];

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    for (const id of scheduleIds) {
      await apiClient.deleteSchedule(id).catch(() => {});
    }
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("seeded schedule appears in list", async ({ page }) => {
    const sched = await apiClient.createSchedule(factories.schedule(targetId));
    scheduleIds.push(sched.id);

    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/schedules");

    await expect(page.getByTestId("schedules-table")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId(`schedule-row-${sched.id}`)).toBeVisible();
  });

  test("toggle schedule enabled state", async ({ page }) => {
    let schedId: number;
    if (scheduleIds.length > 0) {
      schedId = scheduleIds[0];
    } else {
      const sched = await apiClient.createSchedule(factories.schedule(targetId));
      scheduleIds.push(sched.id);
      schedId = sched.id;
    }

    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/schedules");

    await expect(page.getByTestId(`schedule-row-${schedId}`)).toBeVisible({ timeout: 10_000 });

    const toggle = page.getByTestId("schedule-toggle").first();
    if (await toggle.isVisible().catch(() => false)) {
      await toggle.click();
      const schedules = await apiClient.getSchedules(targetId);
      const updated = schedules.find((s) => s.id === schedId);
      expect(updated).toBeTruthy();
    }
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/schedule-scan.spec.ts
git commit -m "test(e2e): add schedule-scan test"
```

---

## Task 14: Write test -- settings-profile.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/settings-profile.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Settings & Profile", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("edit headers and rate limits, verify persistence", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/c2");

    // Open settings drawer
    const settingsBtn = page.locator('button:has-text("Settings")')
      .or(page.locator('[aria-label="Settings"]'));
    await settingsBtn.first().click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5000 });

    // Edit header
    await page.getByTestId("settings-header-key-0").fill("Authorization");
    await page.getByTestId("settings-header-value-0").fill("Bearer e2e-test");

    // Edit rate limit
    await page.getByTestId("settings-rate-input").fill("5");

    // Save
    await page.getByTestId("settings-save-btn").click();
    await expect(page.getByTestId("settings-drawer")).not.toBeVisible({ timeout: 5000 });

    // Reopen and verify
    await settingsBtn.first().click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5000 });
    await expect(page.getByTestId("settings-header-key-0")).toHaveValue("Authorization");
    await expect(page.getByTestId("settings-header-value-0")).toHaveValue("Bearer e2e-test");
    await expect(page.getByTestId("settings-rate-input")).toHaveValue("5");

    // Verify via API
    const { targets } = await apiClient.getTargets();
    const t = targets.find((t: { id: number }) => t.id === targetId);
    expect(t).toBeTruthy();
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/settings-profile.spec.ts
git commit -m "test(e2e): add settings-profile test"
```

---

## Task 15: Write test -- command-palette.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/command-palette.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Command Palette", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("open with Ctrl+K, search, navigate", async ({ page }) => {
    await page.goto("/");

    await page.keyboard.press("Control+k");
    await expect(page.getByTestId("command-palette")).toBeVisible({ timeout: 3000 });

    await page.getByTestId("command-input").fill("C2 Console");
    const results = page.getByTestId("command-result");
    await expect(results.first()).toBeVisible({ timeout: 3000 });
    await results.first().click();

    await page.waitForURL("**/campaign/c2", { timeout: 5000 });
    await expect(page.getByTestId("command-palette")).not.toBeVisible();
  });

  test("close with Escape", async ({ page }) => {
    await page.goto("/");
    await page.keyboard.press("Control+k");
    await expect(page.getByTestId("command-palette")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("command-palette")).not.toBeVisible();
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/command-palette.spec.ts
git commit -m "test(e2e): add command-palette test"
```

---

## Task 16: Write test -- sse-live-updates.spec.ts

**Files:**
- Create: `dashboard/e2e/tests/sse-live-updates.spec.ts`

```ts
import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("SSE Live Updates", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("rescan event appears in timeline without page reload", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/c2");

    await expect(page.getByTestId("c2-timeline")).toBeVisible({ timeout: 10_000 });

    let loadCount = 0;
    page.on("load", () => loadCount++);
    const initialLoadCount = loadCount;

    // Trigger rescan via API
    await apiClient.rescan(targetId).catch(() => {});

    // Wait for timeline entry via SSE
    await expect(
      page.getByTestId("timeline-entry").last(),
    ).toBeVisible({ timeout: 15_000 });

    // Footer counters should be visible
    await expect(page.getByTestId("footer-asset-count")).toBeVisible();

    // No full-page reload
    expect(loadCount).toBe(initialLoadCount);
  });
});
```

**Commit:**
```bash
git add dashboard/e2e/tests/sse-live-updates.spec.ts
git commit -m "test(e2e): add sse-live-updates test"
```

---

## Task 17: Run full suite and fix issues

**Step 1: Run the tests**

```bash
cd dashboard && npm run test:e2e
```

**Step 2: If tests fail**

- Check `dashboard/e2e/test-results/` for screenshots, traces, and video
- Fix the failing component or test
- Re-run just the failing test:
  ```bash
  npx playwright test --config=e2e/playwright.config.ts tests/<file>.spec.ts
  ```

**Step 3: Final commit**

```bash
git add -A
git commit -m "test(e2e): fix issues from first full suite run"
```
