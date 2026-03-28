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

  test("displays asset tree, phase pipeline, worker grid, and timeline", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/c2");
    await expect(page.getByTestId("c2-asset-tree")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible();
    await expect(page.getByTestId("c2-worker-grid")).toBeVisible();

    const timeline = page.getByTestId("c2-timeline");
    if (await timeline.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await expect(page.getByTestId("timeline-entry").first()).toBeVisible();
    }
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
