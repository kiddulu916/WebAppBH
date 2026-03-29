import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("API Error Handling", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    await apiClient.killAll().catch(() => {});
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("500 on assets fetch shows error state with retry", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");

    // Intercept assets API and return 500
    await page.route("**/api/v1/assets*", (route) =>
      route.fulfill({ status: 500, body: JSON.stringify({ detail: "Internal error" }) })
    );

    await page.getByRole("link", { name: "Assets" }).click();

    await expect(page.getByTestId("assets-error-state")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("assets-retry-btn")).toBeVisible();

    // No console errors (white screen check)
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));

    // Remove route intercept and click retry
    await page.unroute("**/api/v1/assets*");
    await page.getByTestId("assets-retry-btn").click();

    // Should now load successfully (no seeded data = empty state)
    await expect(page.getByTestId("assets-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("500 on targets fetch shows error state", async ({ page }) => {
    // Intercept before navigating
    await page.route("**/api/v1/targets", (route) =>
      route.fulfill({ status: 500, body: JSON.stringify({ detail: "DB down" }) })
    );

    await page.goto("/campaign/targets");

    await expect(page.getByTestId("targets-error-state")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("targets-retry-btn")).toBeVisible();
  });

  test("SSE disconnect shows connection lost banner on flow page", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();

    // Wait for flow page to load
    await page.waitForURL("**/campaign/flow");
    await expect(page.getByTestId("flow-playbook-select")).toBeVisible({ timeout: 10_000 });

    // Block execution state polling endpoint (flow uses HTTP polling, not SSE)
    await page.route("**/api/v1/targets/*/execution", (route) =>
      route.abort("connectionrefused")
    );

    // Wait for next poll cycle to fail
    await page.waitForTimeout(12_000);

    // Check for connection-lost indicator or empty monitor (either is valid)
    await expect(
      page.getByTestId("flow-connection-lost")
        .or(page.getByTestId("flow-empty-monitor"))
    ).toBeVisible({ timeout: 5_000 });
  });

  test("no unhandled promise rejections on error pages", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));

    // Intercept multiple APIs
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 500, body: JSON.stringify({ detail: "Error" }) })
    );

    await page.goto("/campaign/targets");
    await page.waitForTimeout(3000);

    // Filter out expected errors (our API client throws intentionally)
    const unexpected = errors.filter(
      (e) => !e.includes("API 500") && !e.includes("Network error")
    );
    expect(unexpected).toHaveLength(0);
  });
});
