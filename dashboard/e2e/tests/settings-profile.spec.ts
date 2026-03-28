import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Settings & Profile", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    const targetData = factories.target();
    baseDomain = targetData.base_domain;
    const res = await apiClient.createTarget(targetData);
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("edit headers and rate limits, verify persistence", async ({ page }) => {
    // Select target via CampaignPicker (navigates to /campaign/c2)
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // The Settings button is icon-only with title="Settings"
    const settingsBtn = page.getByRole("button", { name: "Settings" });
    await settingsBtn.click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5000 });

    await page.getByTestId("settings-header-key-0").fill("Authorization");
    await page.getByTestId("settings-header-value-0").fill("Bearer e2e-test");
    await page.getByTestId("settings-rate-input").fill("5");
    await page.getByTestId("settings-save-btn").click();

    await expect(page.getByTestId("settings-drawer")).not.toBeVisible({ timeout: 5000 });

    // Reopen and verify persistence
    await settingsBtn.click();
    await expect(page.getByTestId("settings-drawer")).toBeVisible({ timeout: 5000 });
    await expect(page.getByTestId("settings-header-key-0")).toHaveValue("Authorization");
    await expect(page.getByTestId("settings-header-value-0")).toHaveValue(
      "Bearer e2e-test",
    );
    await expect(page.getByTestId("settings-rate-input")).toHaveValue("5");
  });
});
