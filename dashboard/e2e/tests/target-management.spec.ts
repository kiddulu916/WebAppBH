import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Target Management", () => {
  const targetIds: number[] = [];

  test.beforeAll(async () => {
    for (let i = 0; i < 3; i++) {
      const res = await apiClient.createTarget(
        factories.target({ company_name: `E2E-Mgmt-${i}-${Date.now()}` }),
      );
      targetIds.push(res.target_id);
    }
  });

  test.afterAll(async () => {
    for (const id of targetIds) {
      await apiClient.deleteTarget(id).catch(() => {});
    }
  });

  test("shows seeded targets in the table", async ({ page }) => {
    await page.goto("/campaign/targets");
    await expect(page.getByTestId("targets-table")).toBeVisible();
    for (const id of targetIds) {
      await expect(page.getByTestId(`target-row-${id}`)).toBeVisible();
    }
  });

  test("search filters the table", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId("target-search-input").fill("E2E-Mgmt-0");
    await expect(page.getByTestId(`target-row-${targetIds[0]}`)).toBeVisible();
    await expect(page.getByTestId(`target-row-${targetIds[1]}`)).not.toBeVisible();
  });

  test("delete removes target from table", async ({ page }) => {
    await page.goto("/campaign/targets");
    const toDelete = targetIds[2];
    await expect(page.getByTestId(`target-row-${toDelete}`)).toBeVisible();

    await page.getByTestId(`target-delete-btn-${toDelete}`).click();

    // Handle confirmation dialog if present
    const confirmInput = page
      .locator('input[placeholder*="company"]')
      .or(page.locator('input[placeholder*="name"]'));
    if (await confirmInput.isVisible({ timeout: 2000 }).catch(() => false)) {
      const { targets } = await apiClient.getTargets();
      const t = targets.find((t) => t.id === toDelete);
      if (t) await confirmInput.fill(t.company_name);
      await page.locator('button:has-text("Delete")').click();
    }

    await expect(page.getByTestId(`target-row-${toDelete}`)).not.toBeVisible({
      timeout: 5000,
    });

    const idx = targetIds.indexOf(toDelete);
    if (idx > -1) targetIds.splice(idx, 1);
  });
});
