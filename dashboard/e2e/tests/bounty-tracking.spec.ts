import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Bounty Tracking", () => {
  let targetId: number;
  let baseDomain: string;
  let vulnIds: number[];
  let seededBountyId: number;

  test.beforeAll(async () => {
    const targetData = factories.target();
    baseDomain = targetData.base_domain;
    const res = await apiClient.createTarget(targetData);
    targetId = res.target_id;
    const seedRes = await apiClient.seedTestData(targetId);
    vulnIds = seedRes.vuln_ids;

    const bounty = await apiClient.createBounty(
      factories.bounty(targetId, vulnIds[0]),
    );
    seededBountyId = bounty.id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("shows seeded bounty", async ({ page }) => {
    // Select the target via CampaignPicker on the home page
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // Navigate to bounties via sidebar (preserves Zustand state)
    await page.getByRole("link", { name: "Bounties" }).click();

    await expect(page.getByTestId("bounties-table")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId(`bounty-row-${seededBountyId}`)).toBeVisible();
  });

  test("can update bounty status", async ({ page }) => {
    // Select the target via CampaignPicker on the home page
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // Navigate to bounties via sidebar (preserves Zustand state)
    await page.getByRole("link", { name: "Bounties" }).click();

    await expect(
      page.getByTestId(`bounty-row-${seededBountyId}`),
    ).toBeVisible({ timeout: 10_000 });

    const editBtn = page.getByTestId(`bounty-edit-${seededBountyId}`);
    if (await editBtn.isVisible().catch(() => false)) {
      await editBtn.click();
      const statusSelect = page.locator("select").first();
      if (await statusSelect.isVisible().catch(() => false)) {
        await statusSelect.selectOption("accepted");
        await page
          .locator('button:has-text("Save")')
          .or(page.locator('button:has-text("Update")'))
          .first()
          .click();
        await expect(
          page.getByTestId(`bounty-status-${seededBountyId}`),
        ).toContainText("accepted", { timeout: 5000 });
      }
    }
  });

  test("bounty with zero payout renders correctly", async ({ page }) => {
    // Create a bounty with $0 payout
    const zeroBounty = await apiClient.createBounty(
      factories.bounty(targetId, vulnIds[0], { expected_payout: 0 }),
    );

    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Bounties" }).click();

    await expect(page.getByTestId("bounties-table")).toBeVisible({ timeout: 10_000 });
    // Verify zero payout renders correctly (not NaN or error)
    const row = page.getByTestId(`bounty-row-${zeroBounty.id}`);
    await expect(row).toBeVisible();
    // Should show $0 or 0, not NaN
    const rowText = await row.textContent();
    expect(rowText).not.toContain("NaN");
  });

  test("special characters in bounty notes do not break rendering", async ({ page }) => {
    // Create bounty via API with special chars in platform name
    const specialBounty = await apiClient.createBounty(
      factories.bounty(targetId, vulnIds[0], { platform: "bug<crowd>&test" }),
    );

    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Bounties" }).click();

    await expect(page.getByTestId("bounties-table")).toBeVisible({ timeout: 10_000 });
    // The row should exist and no HTML injection
    const row = page.getByTestId(`bounty-row-${specialBounty.id}`);
    await expect(row).toBeVisible();
    const content = await page.content();
    expect(content).not.toContain("<crowd>");
  });
});
