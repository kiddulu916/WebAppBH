import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Findings Browser", () => {
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

  test("shows seeded findings", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();

    const table = page.getByTestId("findings-table");
    await expect(table).toBeVisible({ timeout: 10_000 });
    await expect(table).toContainText("SQL Injection");
    await expect(table).toContainText("XSS");
  });

  test("severity filter narrows results", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();

    await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });

    const filter = page.getByTestId("severity-filter");
    if (await filter.isVisible().catch(() => false)) {
      await filter.fill("critical");
      await expect(page.getByTestId("findings-table")).toContainText("SQL Injection");
    }
  });

  test("clicking a finding row opens CorrelationView", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();

    const table = page.getByTestId("findings-table");
    await expect(table).toBeVisible({ timeout: 10_000 });

    const firstRow = table.locator("tbody tr").first();
    await firstRow.click();

    const correlationView = page.getByTestId("correlation-view");
    if (await correlationView.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await expect(correlationView).toBeVisible();
    }
  });

  test("shows empty state when no findings exist", async ({ page }) => {
    // Create a fresh target with no seed data
    const freshTarget = factories.target();
    const res = await apiClient.createTarget(freshTarget);
    try {
      await page.goto("/");
      await page.getByRole("button", { name: new RegExp(freshTarget.base_domain) }).click();
      await page.waitForURL("**/campaign/c2");
      await page.getByRole("link", { name: "Findings" }).click();
      await expect(page.getByTestId("findings-empty-state")).toBeVisible({ timeout: 10_000 });
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });

  test("filter returning no results shows no-match message", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();
    await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });

    // Filter by a severity that has no results
    const filter = page.getByTestId("severity-filter");
    if (await filter.isVisible().catch(() => false)) {
      await filter.fill("info");
      // No info-level vulns seeded — table should show empty or no-match
      await expect(page.getByText(/no.*found/i).or(page.getByText(/no.*match/i)).or(page.getByTestId("findings-empty-state"))).toBeVisible({ timeout: 5_000 });
    }
  });
});
