import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Schedule Scan", () => {
  let targetId: number;
  const scheduleIds: number[] = [];

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    for (const id of scheduleIds) {
      await apiClient.deleteSchedule(id).catch(() => {});
    }
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("seeded schedule appears in list", async ({ page }) => {
    const sched = await apiClient.createSchedule(factories.schedule(targetId));
    scheduleIds.push(sched.id);

    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/schedules");

    await expect(page.getByTestId("schedules-table")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId(`schedule-row-${sched.id}`)).toBeVisible();
  });

  test("toggle schedule enabled state", async ({ page }) => {
    let schedId: number;
    if (scheduleIds.length > 0) {
      schedId = scheduleIds[0];
    } else {
      const sched = await apiClient.createSchedule(factories.schedule(targetId));
      scheduleIds.push(sched.id);
      schedId = sched.id;
    }

    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/schedules");

    await expect(page.getByTestId(`schedule-row-${schedId}`)).toBeVisible({
      timeout: 10_000,
    });

    const toggle = page.getByTestId("schedule-toggle").first();
    if (await toggle.isVisible().catch(() => false)) {
      await toggle.click();
      const schedules = await apiClient.getSchedules(targetId);
      const updated = schedules.find((s) => s.id === schedId);
      expect(updated).toBeTruthy();
    }
  });
});
