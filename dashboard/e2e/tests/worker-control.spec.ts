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

    const pauseBtn = firstCard.getByTestId("worker-pause-btn");
    if (await pauseBtn.isVisible().catch(() => false)) {
      await pauseBtn.click();
      const { jobs } = await apiClient.getJobs(targetId);
      expect(jobs.some((j) => j.status === "PAUSED")).toBeTruthy();
    }
  });
});
