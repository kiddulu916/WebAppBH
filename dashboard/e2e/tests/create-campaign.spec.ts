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

  test("intel enrichment: configure button expands inline form; cancel collapses it", async ({ page }) => {
    await page.goto("/campaign");
    await expect(page.getByTestId("scope-builder")).toBeVisible();
    // Settings link must be gone
    await expect(page.getByTestId("scope-builder").getByRole("link", { name: "Settings" })).not.toBeVisible();

    // Configure button must exist
    const configureBtn = page.getByTestId("intel-configure-btn");
    await expect(configureBtn).toBeVisible();

    // Expand the form
    await configureBtn.click();
    await expect(page.getByTestId("intel-shodan-input")).toBeVisible();
    await expect(page.getByTestId("intel-st-input")).toBeVisible();
    await expect(page.getByTestId("intel-censys-id-input")).toBeVisible();
    await expect(page.getByTestId("intel-censys-secret-input")).toBeVisible();
    await expect(page.getByTestId("intel-save-btn")).toBeVisible();
    await expect(page.getByTestId("intel-cancel-btn")).toBeVisible();

    // Cancel collapses the form
    await page.getByTestId("intel-cancel-btn").click();
    await expect(page.getByTestId("intel-shodan-input")).not.toBeVisible();
    await expect(configureBtn).toBeVisible();
  });

  test("intel enrichment: filling a key and saving collapses the form", async ({ page }) => {
    await page.goto("/campaign");
    await expect(page.getByTestId("scope-builder")).toBeVisible();

    // Open the form
    await page.getByTestId("intel-configure-btn").click();
    await expect(page.getByTestId("intel-shodan-input")).toBeVisible();

    // Fill one key
    await page.getByTestId("intel-shodan-input").fill("test-shodan-key");

    // Save
    await page.getByTestId("intel-save-btn").click();

    // Form should collapse and configure button should return
    await expect(page.getByTestId("intel-shodan-input")).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByTestId("intel-configure-btn")).toBeVisible();
  });

  test("custom headers: add a header in step 1 and see count in review", async ({ page }) => {
    await page.goto("/campaign");
    await expect(page.getByTestId("scope-builder")).toBeVisible();

    // Step 0: fill required fields
    const companyName = `HeaderTest-${Date.now()}`;
    const domain = `headertest-${Date.now()}.example.com`;
    await page.getByTestId("scope-company-input").fill(companyName);
    await page.getByTestId("scope-domain-input").fill(domain);
    await page.getByTestId("scope-next-btn").click();

    // Step 1: add a custom header
    await expect(page.getByTestId("scope-step-1")).toBeVisible();
    await expect(page.getByTestId("header-add-btn")).toBeVisible();
    await page.getByTestId("header-add-btn").click();
    await page.getByTestId("header-key-0").fill("Authorization");
    await page.getByTestId("header-value-0").fill("Bearer e2e-token");
    await page.getByTestId("scope-next-btn").click();

    // Step 2: Playbook
    await expect(page.getByTestId("scope-step-2")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 3: Workflow
    await expect(page.getByTestId("scope-step-3")).toBeVisible();
    await page.getByTestId("scope-next-btn").click();

    // Step 4: Review — header count must appear
    await expect(page.getByTestId("scope-step-4")).toBeVisible();
    await expect(page.getByTestId("review-custom-headers-count")).toHaveText("1");
  });
});
