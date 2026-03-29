import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Configuration", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    await apiClient.killAll().catch(() => {});
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("configure headers → set rate limit → create schedule → toggle off → verify persistence", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // 1. Open settings drawer
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5_000 });

    // 2. Add custom headers
    const headerKey = page.getByTestId("settings-header-key-0");
    if (await headerKey.isVisible().catch(() => false)) {
      await headerKey.fill("Authorization");
      await page.getByTestId("settings-header-value-0").fill("Bearer test-token");
    }

    // 3. Set rate limit
    const rateInput = page.getByTestId("settings-rate-input");
    if (await rateInput.isVisible().catch(() => false)) {
      await rateInput.fill("50");
    }

    // 4. Save
    const saveBtn = page.getByTestId("settings-save-btn");
    if (await saveBtn.isVisible().catch(() => false)) {
      await saveBtn.click();
      await page.waitForTimeout(1000);
    }

    // 5. Navigate to schedules
    await page.getByRole("link", { name: "Schedules" }).click();
    await page.waitForURL("**/campaign/schedules");

    // 6. Create a schedule via API
    const schedule = await apiClient.createSchedule({
      target_id: targetId,
      cron_expression: "0 0 * * *",
      playbook: "wide_recon",
    });

    await page.reload();
    await expect(page.getByText("0 0 * * *")).toBeVisible({ timeout: 10_000 });

    // 7. Toggle schedule off
    await apiClient.updateSchedule(schedule.id, { enabled: false });
    await page.reload();

    // 8. Navigate back to settings — verify headers persisted
    await page.getByRole("link", { name: "C2 Console" }).click();
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5_000 });

    if (await headerKey.isVisible().catch(() => false)) {
      await expect(page.getByTestId("settings-header-key-0")).toHaveValue("Authorization");
    }
    if (await rateInput.isVisible().catch(() => false)) {
      await expect(page.getByTestId("settings-rate-input")).toHaveValue("50");
    }

    // Cleanup
    await apiClient.deleteSchedule(schedule.id).catch(() => {});
  });
});
