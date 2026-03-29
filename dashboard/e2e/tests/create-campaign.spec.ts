import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";

test.describe("Create Campaign", () => {
  let createdTargetId: number | null = null;

  test.afterAll(async () => {
    if (createdTargetId) {
      await apiClient.deleteTarget(createdTargetId).catch(() => {});
    }
  });

  test("complete scope builder wizard and see target in C2", async ({ page }) => {
    await apiClient.killAll().catch(() => {});
    const companyName = `E2E-Wizard-${Date.now()}`;
    const domain = `wizard-${Date.now()}.example.com`;

    await page.goto("/campaign");
    await expect(page.getByTestId("scope-builder")).toBeVisible();

    // Step 0: Target Intel
    await page.getByTestId("scope-company-input").fill(companyName);
    await page.getByTestId("scope-domain-input").fill(domain);
    await page.getByTestId("scope-next-btn").click();

    // Step 1: Scope Rules
    await expect(page.getByTestId("scope-step-1")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 2: Playbook
    await expect(page.getByTestId("scope-step-2")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 3: Workflow
    await expect(page.getByTestId("scope-step-3")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 4: Review & Launch
    await expect(page.getByTestId("scope-step-4")).toBeVisible();
    await page.getByTestId("scope-submit-btn").click();

    // Should redirect to C2
    await page.waitForURL("**/campaign/c2", { timeout: 10_000 });

    // Verify via API
    const { targets } = await apiClient.getTargets();
    const created = targets.find((t) => t.company_name === companyName);
    expect(created).toBeTruthy();
    createdTargetId = created!.id;
  });
});
