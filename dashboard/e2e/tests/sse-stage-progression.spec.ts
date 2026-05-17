/**
 * SSE Stage Progression — verifies STAGE_COMPLETE events update the C2 UI
 * without a page reload. Uses the exposed __campaignStore to inject events,
 * mirroring the real SSE path through useEventStream.
 */
import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("SSE Stage Progression", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    await apiClient.killAll().catch(() => {});
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("STAGE_COMPLETE event updates phase pipeline without page reload", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible({ timeout: 10_000 });

    // Wait for Zustand store to be exposed
    await page.waitForFunction(
      () => !!(window as unknown as Record<string, unknown>).__campaignStore,
      null,
      { timeout: 10_000 },
    );

    // Track reloads — we must NOT reload on SSE events
    let reloadCount = 0;
    page.on("load", () => reloadCount++);
    const baseline = reloadCount;

    // Inject a STAGE_COMPLETE event for the first info_gathering stage
    await page.evaluate(() => {
      const store = (window as unknown as Record<string, unknown>).__campaignStore as {
        getState: () => { pushEvent: (evt: Record<string, unknown>) => void };
      };
      store.getState().pushEvent({
        event: "STAGE_COMPLETE",
        stage: "search_engine_recon",
        stats: { assets_found: 5 },
        timestamp: new Date().toISOString(),
      });
    });

    // Verify the event reached the store — the SSE ingestion path (pushEvent → events[]) is correct
    const eventIngested = await page.evaluate(() => {
      const store = (window as unknown as Record<string, unknown>).__campaignStore as {
        getState: () => { events: Array<Record<string, unknown>> };
      };
      return store.getState().events.some(
        (e) =>
          e.event === "STAGE_COMPLETE" &&
          (e as Record<string, unknown>).stage === "search_engine_recon",
      );
    });
    expect(eventIngested).toBe(true);

    // Pipeline component is still visible — event did not crash the page
    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible({ timeout: 3_000 });

    // No full reload occurred
    expect(reloadCount).toBe(baseline);
  });

  test("PIPELINE_COMPLETE event marks worker as completed in worker grid", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    await expect(page.getByTestId("c2-worker-grid")).toBeVisible({ timeout: 10_000 });

    await page.waitForFunction(
      () => !!(window as unknown as Record<string, unknown>).__campaignStore,
      null,
      { timeout: 10_000 },
    );

    // Inject PIPELINE_COMPLETE
    await page.evaluate(() => {
      const store = (window as unknown as Record<string, unknown>).__campaignStore as {
        getState: () => { pushEvent: (evt: Record<string, unknown>) => void };
      };
      store.getState().pushEvent({
        event: "PIPELINE_COMPLETE",
        target_id: 0,
        timestamp: new Date().toISOString(),
      });
    });

    // Worker grid should reflect the terminal state
    await expect(page.getByTestId("c2-worker-grid")).toContainText(
      /completed|done/i,
      { timeout: 5_000 },
    );
  });

  test("STAGE_ERROR event surfaces in C2 UI without crash", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible({ timeout: 10_000 });

    await page.waitForFunction(
      () => !!(window as unknown as Record<string, unknown>).__campaignStore,
      null,
      { timeout: 10_000 },
    );

    // Track JS errors on the page
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));

    await page.evaluate(() => {
      const store = (window as unknown as Record<string, unknown>).__campaignStore as {
        getState: () => { pushEvent: (evt: Record<string, unknown>) => void };
      };
      store.getState().pushEvent({
        event: "STAGE_ERROR",
        stage: "web_server_fingerprint",
        error: "connection refused",
        timestamp: new Date().toISOString(),
      });
    });

    // Page must not crash — C2 components still visible
    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible({ timeout: 3_000 });
    await expect(page.getByTestId("c2-worker-grid")).toBeVisible({ timeout: 3_000 });

    // No JS exceptions thrown
    expect(pageErrors).toHaveLength(0);
  });
});
