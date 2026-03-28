import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Workflow Builder", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
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

    // Should show all 7 recon stages
    await expect(page.getByTestId("flow-stage-card-passive_discovery")).toBeVisible();
    await expect(page.getByTestId("flow-stage-card-deep_recon")).toBeVisible();

    // Each stage should have a toggle
    await expect(page.getByTestId("flow-stage-toggle-passive_discovery")).toBeVisible();
  });

  test("toggling a stage off grays out the card", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    await page.getByTestId("flow-playbook-select").selectOption("wide_recon");
    await expect(page.getByTestId("flow-stage-card-subdomain_takeover")).toBeVisible();

    // Toggle off subdomain_takeover
    await page.getByTestId("flow-stage-toggle-subdomain_takeover").click();

    // Card should have opacity/disabled styling
    const card = page.getByTestId("flow-stage-card-subdomain_takeover");
    await expect(card).toHaveClass(/opacity/);
  });

  test("execution monitor shows stage statuses for active target", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    // Monitor panel should show stages with seeded job states
    await expect(page.getByTestId("flow-monitor-stage-passive_discovery")).toBeVisible({ timeout: 10_000 });
    // The seeded job has status "RUNNING" with phase "passive_discovery"
    await expect(page.getByTestId("flow-monitor-status-passive_discovery")).toContainText(/running/i);
  });

  test("apply playbook button triggers API call", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    await page.getByTestId("flow-playbook-select").selectOption("api_focused");
    await page.getByTestId("flow-apply-btn").click();

    // Verify the playbook was applied (toast or status change)
    await expect(page.getByText(/applied/i).or(page.getByText(/api_focused/i))).toBeVisible({ timeout: 5_000 });
  });
});
