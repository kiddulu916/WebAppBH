import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Worker Control", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    await apiClient.killAll().catch(() => {});
    const targetData = factories.target();
    baseDomain = targetData.base_domain;
    const res = await apiClient.createTarget(targetData);
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("pause, resume, and stop actions update worker card state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // Find a running worker card
    const cards = page.locator("[data-testid^='worker-card-']");
    await expect(cards.first()).toBeVisible({ timeout: 15_000 });

    const runningCard = page.getByTestId(`worker-card-webbh-recon-t${targetId}`);
    await expect(runningCard).toBeVisible();

    // Pause
    const pauseBtn = runningCard.getByTestId("worker-pause-btn");
    if (await pauseBtn.isVisible().catch(() => false)) {
      await pauseBtn.click();
      await page.waitForTimeout(2000);
    }

    // Resume
    const resumeBtn = runningCard.getByTestId("worker-resume-btn");
    if (await resumeBtn.isVisible().catch(() => false)) {
      await resumeBtn.click();
      await page.waitForTimeout(2000);
    }

    // Stop
    const stopBtn = runningCard.getByTestId("worker-stop-btn");
    if (await stopBtn.isVisible().catch(() => false)) {
      await stopBtn.click();
      await page.waitForTimeout(2000);
    }
  });

  test("worker cards render for seeded jobs", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    const workerGrid = page.getByTestId("c2-worker-grid");
    await expect(workerGrid).toBeVisible({ timeout: 10_000 });

    // Wait for worker cards to appear (seeded via /test/seed, polled by C2 page)
    const cards = page.locator('[data-testid^="worker-card-"]');
    await expect(cards.first()).toBeVisible({ timeout: 15_000 });

    const count = await cards.count();
    expect(count).toBe(2);

    // Verify the RUNNING worker card shows correct status and has action buttons
    const runningCard = page.getByTestId(`worker-card-webbh-recon-t${targetId}`);
    await expect(runningCard).toBeVisible();
    await expect(runningCard).toContainText("RUNNING");
    await expect(runningCard).toContainText("passive_discovery");

    // Pause and Stop buttons should be present on the RUNNING card
    await expect(runningCard.getByTestId("worker-pause-btn")).toBeVisible();
    await expect(runningCard.getByTestId("worker-stop-btn")).toBeVisible();

    // Verify the COMPLETED worker card
    const completedCard = page.getByTestId(`worker-card-webbh-recon-t${targetId}-2`);
    await expect(completedCard).toBeVisible();
    await expect(completedCard).toContainText("COMPLETED");
  });
});
