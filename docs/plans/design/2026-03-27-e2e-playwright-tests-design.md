# E2E Playwright Tests — Design Document

**Date**: 2026-03-27
**Scope**: End-to-end tests for the WebAppBH dashboard using Playwright against a real backend

---

## Goals

- Test the 10 most critical user journeys through the dashboard UI
- Verify that UI actions hit the real orchestrator API and the UI reflects responses
- Self-contained: test harness owns the full Docker stack lifecycle
- Independent: each test seeds its own data and cleans up after itself

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backend | Real (Docker Compose) | No mocks — tests the actual system end-to-end |
| Environment | Self-contained | `globalSetup` starts stack, `globalTeardown` destroys it |
| Data strategy | Independent, self-seeded | Each test creates data in `beforeAll` via API, deletes in `afterAll` |
| Test data for findings | `POST /api/v1/test/seed` endpoint | Inserts fixture assets/vulns; guarded by `ENABLE_TEST_SEED=true` |
| Docker test profile | `docker-compose.test.yml` overlay | Activates seed endpoint only in test runs |
| Selectors | `data-testid` attributes | Decoupled from styling; ~12 component files need testid additions |
| Browser | Chromium only | Bug bounty tool, not consumer product |
| Parallelism | Sequential (`workers: 1`) | Shared Docker stack; avoid race conditions |
| Retries | 1 | Catches transient Docker timing issues |
| Artifacts | Traces, screenshots, video on failure only | Small CI artifacts, full debugging context when needed |

---

## Project Structure

```
dashboard/
  e2e/
    playwright.config.ts          # Playwright config (baseURL, timeouts, projects)
    global-setup.ts               # docker compose up + health-check polling
    global-teardown.ts            # docker compose down -v
    helpers/
      api-client.ts               # Direct orchestrator API wrapper for seeding/cleanup
      wait-for-services.ts        # Poll health endpoints until ready
      seed-factories.ts           # Build valid seed payloads with unique timestamps
    tests/
      create-campaign.spec.ts
      target-management.spec.ts
      c2-console.spec.ts
      worker-control.spec.ts
      findings-browser.spec.ts
      bounty-tracking.spec.ts
      schedule-scan.spec.ts
      settings-profile.spec.ts
      command-palette.spec.ts
      sse-live-updates.spec.ts
```

---

## Global Setup & Teardown

### `global-setup.ts`
1. Run `docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build` from repo root
2. Poll `GET http://localhost:8001/api/v1/health` until 200 (timeout: 120s, poll interval: 2s)
3. Poll `GET http://localhost:3000` until 200
4. If stack is already running, health checks pass immediately — no rebuild

### `global-teardown.ts`
1. Run `docker compose -f docker-compose.yml -f docker-compose.test.yml down -v`
2. Volumes destroyed — guarantees clean DB next run

---

## API Client (`helpers/api-client.ts`)

Plain `fetch` wrapper around orchestrator REST API. Used only in `beforeAll`/`afterAll` hooks for seeding and cleanup. Not used during test execution — the UI drives all interactions.

### Methods
- **Targets**: `createTarget`, `getTargets`, `deleteTarget`, `cleanSlate`, `rescan`
- **Data retrieval**: `getAssets`, `getVulns`, `getCloudAssets`, `getJobs`
- **Worker control**: `controlWorker`
- **Bounties**: `createBounty`, `getBounties`, `updateBounty`
- **Schedules**: `createSchedule`, `deleteSchedule`
- **Test-only**: `seedTestData(targetId)` — calls `POST /api/v1/test/seed`
- **Utility**: `health`, `search`

All methods include `X-API-KEY` header from env.

## Seed Factories (`helpers/seed-factories.ts`)

Build valid payloads with `Date.now().toString(36)` suffix for uniqueness:
- `factories.target(overrides?)` — `TargetCreate` with unique `company_name` and `base_domain`
- `factories.bounty(targetId, overrides?)` — `BountyCreate`
- `factories.schedule(targetId, overrides?)` — `ScheduleCreate`

---

## Test Seed Endpoint

### `POST /api/v1/test/seed`

Added to orchestrator. Guarded by `ENABLE_TEST_SEED=true` env var (returns 404 otherwise).

**Request**: `{ "target_id": <int> }`

**Inserts**:
- 5 assets: 3 subdomains (`sub1.example.com`, `sub2.example.com`, `admin.example.com`), 2 IPs
- 2 locations: port 80/HTTP, port 443/HTTPS on first asset
- 3 vulnerabilities: 1 critical (SQL Injection), 1 medium (XSS), 1 low (Info Disclosure)
- 2 cloud assets: 1 public S3 bucket, 1 private Azure blob
- 1 alert: critical vuln alert

Fixture data is deterministic — same structure every run, different IDs. Tests assert on known values (e.g., "expect a critical vuln containing 'SQL Injection'").

### `docker-compose.test.yml`

```yaml
services:
  orchestrator:
    environment:
      - ENABLE_TEST_SEED=true
```

---

## Playwright Configuration

```ts
defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  timeout: 30_000,
  retries: 1,
  workers: 1,
  fullyParallel: false,
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  reporter: [['html', { open: 'never' }], ['list']],
});
```

### npm scripts (added to dashboard/package.json)

```json
{
  "test:e2e": "playwright test",
  "test:e2e:ui": "playwright test --ui",
  "test:e2e:debug": "playwright test --debug"
}
```

---

## Test Files — Coverage Map

### 1. `create-campaign.spec.ts`
- **Seeds**: None (this IS the creation flow)
- **Flow**: Navigate to `/campaign` → complete 5-step ScopeBuilder wizard → submit
- **Asserts**: Redirects to targets page, new target visible in table
- **Cleanup**: Delete the created target via API

### 2. `target-management.spec.ts`
- **Seeds**: 3 targets via API
- **Flow**: Navigate to `/campaign/targets` → search → sort → delete one
- **Asserts**: Table shows 3 rows, search filters, sort reorders, delete removes row, API confirms 404

### 3. `c2-console.spec.ts`
- **Seeds**: 1 target + `seedTestData` + `rescan` to kick off a job
- **Flow**: Navigate to `/campaign/c2` → select target
- **Asserts**: Asset tree renders with seeded assets, worker grid shows cards, phase pipeline shows stages, timeline has entries

### 4. `worker-control.spec.ts`
- **Seeds**: 1 target + `rescan` → poll until a job is RUNNING
- **Flow**: In C2, click pause → resume → stop on a worker card
- **Asserts**: UI status changes after each action, API `getJobs()` confirms status

### 5. `findings-browser.spec.ts`
- **Seeds**: 1 target + `seedTestData`
- **Flow**: Navigate to `/campaign/findings` → filter by severity → click row
- **Asserts**: Table shows seeded rows, filter narrows results, CorrelationView opens

### 6. `bounty-tracking.spec.ts`
- **Seeds**: 1 target + 1 bounty via API
- **Flow**: Navigate to `/campaign/bounties` → verify seeded bounty → create new via UI → update status
- **Asserts**: Both bounties visible, status badge updates

### 7. `schedule-scan.spec.ts`
- **Seeds**: 1 target
- **Flow**: Navigate to schedules → create via UI → toggle enabled → delete
- **Asserts**: Schedule appears, toggle reflects state, deletion removes row, API confirms gone

### 8. `settings-profile.spec.ts`
- **Seeds**: 1 target
- **Flow**: In C2, open SettingsDrawer → edit headers → edit rate limits → save → reopen
- **Asserts**: Values persisted in UI and confirmed via API `getTargets()`

### 9. `command-palette.spec.ts`
- **Seeds**: 1 target
- **Flow**: Press Ctrl+K → type target name → select result → verify navigation. Repeat for page name.
- **Asserts**: Palette opens, results match, navigation works

### 10. `sse-live-updates.spec.ts`
- **Seeds**: 1 target + `seedTestData`
- **Flow**: On C2 page, trigger `rescan` via API → wait for DOM update
- **Asserts**: New timeline entry contains `RERUN_STARTED` (10s timeout), footer counter increments, no full-page reload

---

## Data-testid Strategy

Testids added to source components. Naming: `{component}-{element}` in kebab-case, dynamic IDs: `{component}-{element}-{id}`.

| Component | Testids |
|-----------|---------|
| ScopeBuilder | `scope-step-{n}`, `scope-next-btn`, `scope-submit-btn`, `scope-domain-input` |
| Targets table | `targets-table`, `target-row-{id}`, `target-delete-btn`, `target-search-input` |
| C2 page | `c2-asset-tree`, `c2-worker-grid`, `c2-phase-pipeline`, `c2-timeline` |
| WorkerCard | `worker-card-{name}`, `worker-pause-btn`, `worker-stop-btn`, `worker-resume-btn` |
| DataTable | `findings-table`, `findings-row`, `severity-filter`, `correlation-view` |
| Bounties | `bounties-table`, `bounty-row-{id}`, `bounty-create-btn`, `bounty-status-badge` |
| Schedules | `schedules-table`, `schedule-row-{id}`, `schedule-toggle`, `schedule-create-btn` |
| SettingsDrawer | `settings-drawer`, `settings-headers-input`, `settings-rate-input`, `settings-save-btn` |
| CommandPalette | `command-palette`, `command-input`, `command-result` |
| CampaignTimeline | `timeline-entry` |
| FooterBar | `footer-asset-count`, `footer-vuln-count` |

---

## Tricky Scenarios

### SSE Event Assertions
Trigger event via API, then wait for DOM update with extended timeout:
```ts
await apiClient.rescan(targetId);
await expect(page.locator('[data-testid="timeline-entry"]').last())
  .toContainText('RERUN_STARTED', { timeout: 10_000 });
```

### Worker Control Timing
Poll `getJobs()` until a RUNNING job exists before interacting with UI:
```ts
await pollUntil(() => apiClient.getJobs(targetId),
  jobs => jobs.some(j => j.status === 'RUNNING'), 15_000);
```

### Findings Need Data
Uses `POST /api/v1/test/seed` to insert fixture assets, vulns, cloud assets. No real pipeline needed.

---

## Implementation Order

1. Add `data-testid` attributes to ~12 dashboard component files
2. Add `POST /api/v1/test/seed` endpoint to orchestrator (guarded by `ENABLE_TEST_SEED`)
3. Create `docker-compose.test.yml` overlay
4. Scaffold `e2e/` directory (config, helpers, global setup/teardown)
5. Write test files 1-10 in order (each builds confidence in the helpers)
6. Add npm scripts to `dashboard/package.json`
7. Install Playwright: `npm install -D @playwright/test && npx playwright install chromium`
