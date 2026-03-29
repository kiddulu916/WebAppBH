import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Target Management", () => {
  const targetIds: number[] = [];
  const baseDomains: string[] = [];

  test.beforeAll(async () => {
    for (let i = 0; i < 3; i++) {
      await apiClient.killAll().catch(() => {});
      const targetData = factories.target({ company_name: `E2E-Mgmt-${i}-${Date.now()}` });
      baseDomains.push(targetData.base_domain);
      const res = await apiClient.createTarget(targetData);
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
    const domainToDelete = baseDomains[2];
    await expect(page.getByTestId(`target-row-${toDelete}`)).toBeVisible();

    // Open context menu then click delete
    await page.getByTestId(`target-menu-btn-${toDelete}`).click();
    await page.getByTestId(`target-delete-btn-${toDelete}`).click();

    // Handle confirmation dialog — type the base_domain to confirm
    const confirmInput = page.locator(`input[placeholder="${domainToDelete}"]`);
    await expect(confirmInput).toBeVisible({ timeout: 3000 });
    await confirmInput.fill(domainToDelete);
    await page.getByRole("button", { name: "Delete Target" }).click();

    await expect(page.getByTestId(`target-row-${toDelete}`)).not.toBeVisible({
      timeout: 5000,
    });

    const idx = targetIds.indexOf(toDelete);
    if (idx > -1) targetIds.splice(idx, 1);
  });
});
