import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("SSE Live Updates", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    const targetData = factories.target();
    baseDomain = targetData.base_domain;
    const res = await apiClient.createTarget(targetData);
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("seeded jobs render in campaign timeline", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // Seeded jobs appear via the initial /status poll
    await expect(page.getByTestId("timeline-entry").first()).toBeVisible({
      timeout: 15_000,
    });

    const entries = page.getByTestId("timeline-entry");
    await expect(entries).toHaveCount(2);
  });

  test("NEW_ASSET event updates tree without page reload", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    await expect(page.getByTestId("c2-asset-tree")).toBeVisible({ timeout: 10_000 });

    // Wait for the Zustand store to be exposed on window
    await page.waitForFunction(
      () => !!(window as Record<string, unknown>).__campaignStore,
      null,
      { timeout: 10_000 },
    );

    // Track full page reloads
    let loadCount = 0;
    page.on("load", () => loadCount++);
    const initialLoadCount = loadCount;

    // Inject a NEW_ASSET event via the exposed Zustand store
    // (mirrors what useEventStream does when receiving an SSE event)
    const newAssetValue = `sse-test-${Date.now()}.${baseDomain}`;
    await page.evaluate((assetValue) => {
      const store = (window as Record<string, unknown>).__campaignStore as {
        getState: () => { pushEvent: (evt: Record<string, unknown>) => void };
      };
      store.getState().pushEvent({
        event: "NEW_ASSET",
        asset_type: "subdomain",
        asset_value: assetValue,
        target_id: 0,
        timestamp: new Date().toISOString(),
      });
    }, newAssetValue);

    // Verify the new asset appears in the tree (no reload)
    await expect(
      page.getByTestId("c2-asset-tree").getByText(newAssetValue),
    ).toBeVisible({ timeout: 10_000 });

    // Confirm no full page reload occurred
    expect(loadCount).toBe(initialLoadCount);
  });
});
