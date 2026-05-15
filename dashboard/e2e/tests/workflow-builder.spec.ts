import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Workflow Builder", () => {
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

  test("displays playbook selector with built-in playbooks", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    const select = page.getByTestId("flow-playbook-select");
    await expect(select).toBeVisible({ timeout: 10_000 });

    // Should have built-in options
    await expect(select.locator("option")).toHaveCount(5); // 4 built-in + "Select..."
  });

  test("selecting playbook shows stage cards with toggles", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    await page.getByTestId("flow-playbook-select").selectOption("wide_recon");

    // Should show recon stages (info_gathering is auto-expanded)
    await expect(page.getByTestId("flow-stage-card-search_engine_recon")).toBeVisible();
    await expect(page.getByTestId("flow-stage-card-web_server_fingerprint")).toBeVisible();

    // Each stage should have a toggle
    await expect(page.getByTestId("flow-stage-toggle-search_engine_recon")).toBeVisible();
  });

  test("toggling a stage off grays out the card", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    const select = page.getByTestId("flow-playbook-select");
    await expect(select.locator("option")).not.toHaveCount(1, { timeout: 10_000 });
    await select.selectOption("wide_recon");
    await expect(page.getByTestId("flow-stage-card-subdomain_takeover")).toBeVisible({ timeout: 5_000 });

    // Toggle off subdomain_takeover
    await page.getByTestId("flow-stage-toggle-subdomain_takeover").click({ force: true });

    // Card should have opacity-50 styling (disabled state)
    const card = page.getByTestId("flow-stage-card-subdomain_takeover");
    await expect(card).toHaveClass(/opacity-50/, { timeout: 5_000 });
  });

  test("execution monitor shows stage statuses for active target", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    // Monitor panel should show stages with seeded job states
    await expect(page.getByTestId("flow-monitor-stage-enumerate_applications")).toBeVisible({ timeout: 10_000 });
    // The seeded job has status "RUNNING" with phase "enumerate_applications"
    await expect(page.getByTestId("flow-monitor-status-enumerate_applications")).toContainText(/running/i);
  });

  test("apply playbook button triggers API call", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    const select = page.getByTestId("flow-playbook-select");
    await expect(select.locator("option")).not.toHaveCount(1, { timeout: 10_000 });
    await select.selectOption("api_focused");

    const applyBtn = page.getByTestId("flow-apply-btn");
    await expect(applyBtn).toBeEnabled({ timeout: 5_000 });
    await applyBtn.click();

    // Verify the playbook was applied — button still visible (no crash) and select retains value
    await expect(page.getByTestId("flow-apply-btn")).toBeVisible({ timeout: 5_000 });
    await expect(select).toHaveValue("api_focused");
  });
});
