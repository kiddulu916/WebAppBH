import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Edge Cases", () => {
  test.beforeEach(async () => {
    await apiClient.killAll().catch(() => {});
  });

  test("special characters in company name render safely", async ({ page }) => {
    const target = factories.target({
      company_name: `O'Reilly & Co. <test> "quoted"`,
    });
    const res = await apiClient.createTarget(target);

    try {
      await page.goto("/campaign/targets");
      await expect(page.getByText(`O'Reilly & Co.`)).toBeVisible({ timeout: 10_000 });
      // Verify no HTML injection — the text should be escaped
      const content = await page.content();
      expect(content).not.toContain("<test>");
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });

  test("long domain does not break table layout", async ({ page }) => {
    const longDomain = "a".repeat(60) + ".example.com";
    const target = factories.target({ base_domain: longDomain });
    const res = await apiClient.createTarget(target);

    try {
      await page.goto("/campaign/targets");
      // Table should be visible and not overflow horizontally
      const table = page.locator("table").first();
      await expect(table).toBeVisible({ timeout: 10_000 });
      const box = await table.boundingBox();
      const viewport = page.viewportSize();
      expect(box!.width).toBeLessThanOrEqual(viewport!.width);
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });

  test("rapid double-click on create does not duplicate target", async ({ page }) => {
    await page.goto("/campaign");

    // Fill scope builder (step 1)
    await page.getByTestId("scope-company-input").fill("DoubleClick-Corp");
    await page.getByTestId("scope-domain-input").fill("doubleclick.example.com");
    await page.getByTestId("scope-next-btn").click();

    // Skip through remaining steps to submit
    for (let i = 0; i < 3; i++) {
      await page.getByTestId("scope-next-btn").click();
    }

    // Double-click submit rapidly
    const submit = page.getByTestId("scope-submit-btn");
    await submit.dblclick();

    // Wait for navigation
    await page.waitForURL("**/campaign/c2", { timeout: 10_000 });

    // Check targets — should only have 1 with this name
    const targets = await apiClient.getTargets();
    const matches = targets.targets.filter(
      (t) => t.company_name === "DoubleClick-Corp"
    );
    expect(matches.length).toBe(1);

    // Cleanup
    for (const t of matches) {
      await apiClient.deleteTarget(t.id).catch(() => {});
    }
  });

  test("fast typing in command palette does not crash", async ({ page }) => {
    const target = factories.target();
    const res = await apiClient.createTarget(target);

    try {
      await page.goto("/");
      await page.getByRole("button", { name: new RegExp(target.base_domain) }).click();
      await page.waitForURL("**/campaign/c2");

      // Open command palette
      await page.keyboard.press("Meta+k");
      const input = page.getByTestId("command-input");
      await expect(input).toBeVisible({ timeout: 3_000 });

      // Type very fast
      await input.type("asdfghjklqwertyuiop", { delay: 10 });
      await page.waitForTimeout(500);

      // Should still be responsive — no crash
      await expect(input).toBeVisible();

      // Escape to close
      await page.keyboard.press("Escape");
      await expect(page.getByTestId("command-palette")).not.toBeVisible();
    } finally {
      await apiClient.deleteTarget(res.target_id).catch(() => {});
    }
  });
});
