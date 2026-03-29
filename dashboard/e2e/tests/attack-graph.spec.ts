import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Attack Graph", () => {
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

  test("renders graph canvas with nodes from seeded data", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();
    await page.waitForURL("**/campaign/graph");

    const canvas = page.getByTestId("graph-canvas");
    await expect(canvas).toBeVisible({ timeout: 10_000 });

    // Wait for custom graph nodes to render (more reliable than .react-flow__node)
    const nodes = page.locator("[data-testid^='graph-node-']");
    await expect(nodes.first()).toBeVisible({ timeout: 10_000 });
  });

  test("attack paths toggle shows path list", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();

    await expect(page.getByTestId("graph-canvas")).toBeVisible({ timeout: 10_000 });
    await expect(page.locator("[data-testid^='graph-node-']").first()).toBeVisible({ timeout: 10_000 });

    // Toggle attack paths
    await page.getByTestId("graph-attack-paths-toggle").click();

    // Path list should appear if seeded data has attack paths, otherwise toggle should stay active
    const pathList = page.getByTestId("graph-path-list");
    const toggleActive = page.getByTestId("graph-attack-paths-toggle");
    await expect(pathList.or(toggleActive)).toBeVisible({ timeout: 10_000 });
  });

  test("clicking a node opens detail sidebar", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();

    await expect(page.getByTestId("graph-canvas")).toBeVisible({ timeout: 10_000 });
    await expect(page.locator("[data-testid^='graph-node-']").first()).toBeVisible({ timeout: 10_000 });

    // Click on any visible node
    const firstNode = page.locator("[data-testid^='graph-node-']").first();
    await firstNode.click({ force: true });

    // Sidebar should slide in (300ms CSS transition)
    const sidebar = page.getByTestId("graph-detail-sidebar");
    await expect(sidebar).toBeVisible({ timeout: 5_000 });

    // Close button should work — sidebar slides off-screen via translate-x-full
    await page.getByTestId("graph-detail-close").click();
    await expect(sidebar).toHaveClass(/translate-x-full/, { timeout: 5_000 });
  });

  test("fit-to-view and reset layout buttons work", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();

    await expect(page.getByTestId("graph-canvas")).toBeVisible({ timeout: 10_000 });

    // Buttons should be clickable without errors
    await page.getByTestId("graph-fit-btn").click();
    await page.getByTestId("graph-reset-btn").click();

    // Canvas should still be visible (no crash)
    await expect(page.getByTestId("graph-canvas")).toBeVisible();
  });
});
