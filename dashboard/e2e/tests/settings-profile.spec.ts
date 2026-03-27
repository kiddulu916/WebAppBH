import { test, expect } from "@playwright/test";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Settings & Profile", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("edit headers and rate limits, verify persistence", async ({ page }) => {
    await page.goto("/campaign/targets");
    await page.getByTestId(`target-row-${targetId}`).click();
    await page.goto("/campaign/c2");

    const settingsBtn = page
      .locator('button:has-text("Settings")')
      .or(page.locator('[aria-label="Settings"]'));
    await settingsBtn.first().click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5000 });

    await page.getByTestId("settings-header-key-0").fill("Authorization");
    await page.getByTestId("settings-header-value-0").fill("Bearer e2e-test");
    await page.getByTestId("settings-rate-input").fill("5");
    await page.getByTestId("settings-save-btn").click();

    await expect(page.getByTestId("settings-drawer")).not.toBeVisible({ timeout: 5000 });

    // Reopen and verify persistence
    await settingsBtn.first().click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5000 });
    await expect(page.getByTestId("settings-header-key-0")).toHaveValue("Authorization");
    await expect(page.getByTestId("settings-header-value-0")).toHaveValue(
      "Bearer e2e-test",
    );
    await expect(page.getByTestId("settings-rate-input")).toHaveValue("5");
  });
});
