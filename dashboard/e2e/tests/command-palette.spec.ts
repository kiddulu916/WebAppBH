import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Command Palette", () => {
  let targetId: number;

  test.beforeAll(async () => {
    const res = await apiClient.createTarget(factories.target());
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("open with Ctrl+K, search, navigate", async ({ page }) => {
    await page.goto("/");

    // Click the ⌘K button in the TopBar to open the command palette
    // (Chromium intercepts the native Ctrl+K keyboard shortcut)
    await page.getByRole("button", { name: "K", exact: true }).click();
    await expect(page.getByTestId("command-palette")).toBeVisible({ timeout: 3000 });

    await page.getByTestId("command-input").fill("C2 Console");
    const results = page.getByTestId("command-result");
    await expect(results.first()).toBeVisible({ timeout: 3000 });
    await results.first().click();

    await page.waitForURL("**/campaign/c2", { timeout: 5000 });
    await expect(page.getByTestId("command-palette")).not.toBeVisible();
  });

  test("close with Escape", async ({ page }) => {
    await page.goto("/");

    await page.getByRole("button", { name: "K", exact: true }).click();
    await expect(page.getByTestId("command-palette")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("command-palette")).not.toBeVisible();
  });
});
