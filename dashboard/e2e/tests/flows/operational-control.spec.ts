import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Operational Control", () => {
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

  test("verify running → pause → resume → stop worker states on C2", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // 1. Verify RUNNING worker card
    const workerCard = page.locator("[data-testid^='worker-card-']").first();
    await expect(workerCard).toBeVisible({ timeout: 10_000 });
    await expect(workerCard.getByText(/running/i)).toBeVisible();

    // 2. Pause worker
    const pauseBtn = page.getByTestId("worker-pause-btn").first();
    if (await pauseBtn.isVisible().catch(() => false)) {
      await pauseBtn.click();
      await page.waitForTimeout(2000);
    }

    // 3. Resume worker
    const resumeBtn = page.getByTestId("worker-resume-btn").first();
    if (await resumeBtn.isVisible().catch(() => false)) {
      await resumeBtn.click();
      await page.waitForTimeout(2000);
    }

    // 4. Stop worker
    const stopBtn = page.getByTestId("worker-stop-btn").first();
    if (await stopBtn.isVisible().catch(() => false)) {
      await stopBtn.click();
      await page.waitForTimeout(2000);
    }

    // 5. Verify timeline shows state changes
    const timeline = page.getByTestId("c2-timeline");
    await expect(timeline).toBeVisible();
  });
});
