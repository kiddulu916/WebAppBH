import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Assets Inventory", () => {
  let targetId: number;
  let baseDomain: string;
  let seedResult: { asset_ids: number[]; vuln_ids: number[] };

  test.beforeAll(async () => {
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    seedResult = await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("displays seeded assets in table with correct columns", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();
    await page.waitForURL("**/campaign/assets");

    const table = page.getByTestId("assets-table");
    await expect(table).toBeVisible({ timeout: 10_000 });

    // Verify seeded assets appear (5 assets from seed)
    await expect(page.getByText(`sub1.${baseDomain}`)).toBeVisible();
    await expect(page.getByText(`sub2.${baseDomain}`)).toBeVisible();
    await expect(page.getByText("10.0.0.1")).toBeVisible();
  });

  test("search filters assets by hostname", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    const searchInput = page.getByTestId("assets-search");
    await searchInput.fill("admin");

    // Only admin subdomain should be visible
    await expect(page.getByText(`admin.${baseDomain}`)).toBeVisible();
    await expect(page.getByText("10.0.0.1")).not.toBeVisible();
  });

  test("expands row to show locations tab", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    // Click expand on first asset row
    const firstAssetId = seedResult.asset_ids[0];
    await page.getByTestId(`asset-expand-btn-${firstAssetId}`).click();

    // Detail panel should appear with locations tab active
    const panel = page.getByTestId(`asset-detail-panel-${firstAssetId}`);
    await expect(panel).toBeVisible({ timeout: 5_000 });

    // Locations tab should show port 80 and 443
    await expect(panel.getByText("80")).toBeVisible();
    await expect(panel.getByText("443")).toBeVisible();
  });

  test("switches between detail tabs", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    const firstAssetId = seedResult.asset_ids[0];
    await page.getByTestId(`asset-expand-btn-${firstAssetId}`).click();

    const panel = page.getByTestId(`asset-detail-panel-${firstAssetId}`);
    await expect(panel).toBeVisible({ timeout: 5_000 });

    // Switch to Vulnerabilities tab
    await page.getByTestId("asset-tab-vulns").click();
    await expect(panel.getByText("SQL Injection")).toBeVisible({ timeout: 5_000 });

    // Switch to Cloud tab
    await page.getByTestId("asset-tab-cloud").click();
    await expect(panel.getByText("s3_bucket").or(panel.getByText("S3"))).toBeVisible({ timeout: 5_000 });
  });

  test("type filter narrows results", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-table")).toBeVisible({ timeout: 10_000 });

    // Filter by IP type
    await page.getByTestId("assets-type-filter").selectOption("ip");

    // Only IPs should show
    await expect(page.getByText("10.0.0.1")).toBeVisible();
    await expect(page.getByText(`sub1.${baseDomain}`)).not.toBeVisible();
  });
});
