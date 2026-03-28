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

    await apiClient.rescan(targetId).catch(() => {});

    await expect(page.getByTestId("timeline-entry").last()).toContainText(
      /RERUN_STARTED|recon|RUNNING/i,
      { timeout: 15_000 },
    );

    await expect(page.getByTestId("footer-asset-count")).toBeVisible();

    expect(loadCount).toBe(initialLoadCount);
  });
});
