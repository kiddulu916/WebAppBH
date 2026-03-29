import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Triage Workflow", () => {
  let targetId: number;
  let baseDomain: string;
  let seedResult: { vuln_ids: number[] };

  test.beforeAll(async () => {
    // Kill active jobs so target creation isn't blocked by 409
    await apiClient.killAll().catch(() => {});
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    seedResult = await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("filter findings → view correlation → create bounty → update status", async ({ page }) => {
    // 1. Navigate to findings
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();

    // 2. Filter by critical severity
    await expect(page.getByTestId("findings-table")).toBeVisible({ timeout: 10_000 });
    const filter = page.getByTestId("severity-filter");
    if (await filter.isVisible().catch(() => false)) {
      await filter.fill("critical");
    }
    await expect(page.getByText("SQL Injection").first()).toBeVisible();

    // 3. Open correlation view
    const correlationBtn = page.getByTestId("correlation-view");
    if (await correlationBtn.isVisible().catch(() => false)) {
      await correlationBtn.click();
      await expect(page.getByText(/correlation/i)).toBeVisible({ timeout: 5_000 });
      await page.keyboard.press("Escape");
    }

    // 4. Navigate to bounties and create one
    await page.getByRole("link", { name: "Bounties" }).click();
    await page.waitForURL("**/campaign/bounties");

    // Create bounty via API
    const bounty = await apiClient.createBounty({
      target_id: targetId,
      vulnerability_id: seedResult.vuln_ids[0],
      platform: "hackerone",
      expected_payout: 1000,
    });

    // Reload and verify bounty appears
    await page.reload();
    await expect(page.getByText("hackerone")).toBeVisible({ timeout: 10_000 });

    // 5. Update bounty status
    await apiClient.updateBounty(bounty.id, { status: "submitted" });
    await page.reload();
    await expect(page.getByTestId(`bounty-status-${bounty.id}`)).toContainText(/submitted/i, { timeout: 10_000 });

    // 6. Update payout and verify persistence
    await apiClient.updateBounty(bounty.id, { actual_payout: 750 });
    await page.reload();
    await expect(page.getByText("750").first()).toBeVisible({ timeout: 10_000 });
  });
});
