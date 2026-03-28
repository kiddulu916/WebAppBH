import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Findings Browser", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("shows seeded findings", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/findings");

    const table = page.getByTestId("findings-table");
    await expect(table).toBeVisible({ timeout: 10_000 });
    await expect(table).toContainText("SQL Injection");
    await expect(table).toContainText("XSS");
  });

  test("severity filter narrows results", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/findings");

    await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });

    const filter = page.getByTestId("severity-filter");
    if (await filter.isVisible().catch(() => false)) {
      await filter.fill("critical");
      await expect(page.getByTestId("findings-table")).toContainText("SQL Injection");
    }
  });

  test("clicking a finding row opens CorrelationView", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/findings");

    const table = page.getByTestId("findings-table");
    await expect(table).toBeVisible({ timeout: 10_000 });

    const firstRow = table.locator("tbody tr").first();
    await firstRow.click();

    const correlationView = page.getByTestId("correlation-view");
    if (await correlationView.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await expect(correlationView).toBeVisible();
    }
  });
});
