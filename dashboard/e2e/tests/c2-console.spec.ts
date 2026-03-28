import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("C2 Console", () => {
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

  test("displays asset tree, phase pipeline, worker grid, and timeline", async ({ page }) => {
    // Select target via CampaignPicker (navigates to /campaign/c2)
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    await expect(page.getByTestId("c2-asset-tree")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible();
    await expect(page.getByTestId("c2-worker-grid")).toBeVisible();

    const timeline = page.getByTestId("c2-timeline");
    if (await timeline.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await expect(page.getByTestId("timeline-entry").first()).toBeVisible();
    }
  });

  test("shows seeded assets in asset tree", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    const tree = page.getByTestId("c2-asset-tree");
    await expect(tree).toBeVisible({ timeout: 10_000 });
    await expect(tree).toContainText("sub1.");
    await expect(tree).toContainText("10.0.0.1");
  });
});
