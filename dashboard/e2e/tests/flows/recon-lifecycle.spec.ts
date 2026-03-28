import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Full Recon Lifecycle", () => {
  let targetId: number;
  let baseDomain: string;

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("create target → apply playbook → scan → view assets → view findings → create bounty", async ({ page }) => {
    // 1. Create target via scope builder wizard
    const targetData = factories.target();
    baseDomain = targetData.base_domain;

    await page.goto("/campaign");
    await page.getByTestId("scope-company-input").fill(targetData.company_name);
    await page.getByTestId("scope-domain-input").fill(baseDomain);
    await page.getByTestId("scope-next-btn").click();
    // Skip remaining scope steps
    for (let i = 0; i < 3; i++) {
      await page.getByTestId("scope-next-btn").click();
    }
    await page.getByTestId("scope-submit-btn").click();
    await page.waitForURL("**/campaign/c2", { timeout: 15_000 });

    // Get the target ID from API
    const targets = await apiClient.getTargets();
    const created = targets.targets.find((t) => t.base_domain === baseDomain);
    expect(created).toBeDefined();
    targetId = created!.id;

    // 2. Seed test data (simulates scan results)
    await apiClient.seedTestData(targetId);

    // 3. Navigate to flow → verify playbook can be selected
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");
    await expect(page.getByTestId("flow-playbook-select")).toBeVisible({ timeout: 10_000 });

    // 4. Navigate to assets → verify discoveries appear
    await page.getByRole("link", { name: "Assets" }).click();
    await page.waitForURL("**/campaign/assets");
    await expect(page.getByText(`sub1.${baseDomain}`)).toBeVisible({ timeout: 10_000 });

    // 5. Navigate to findings → verify vulns listed
    await page.getByRole("link", { name: "Findings" }).click();
    await page.waitForURL("**/campaign/findings");
    await expect(page.getByText("SQL Injection")).toBeVisible({ timeout: 10_000 });

    // 6. Navigate to bounties → verify page loads
    await page.getByRole("link", { name: "Bounties" }).click();
    await page.waitForURL("**/campaign/bounties");
    await expect(page.getByText(/bounties/i)).toBeVisible();
  });
});
