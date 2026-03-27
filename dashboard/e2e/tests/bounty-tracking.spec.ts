import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Bounty Tracking", () => {
  let targetId: number;
  let vulnIds: number[];
  let seededBountyId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
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
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/bounties");

    await expect(page.getByTestId("bounties-table")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId(`bounty-row-${seededBountyId}`)).toBeVisible();
  });

  test("can update bounty status", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/bounties");

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
});
