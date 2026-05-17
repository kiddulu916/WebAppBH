/**
 * Live Pipeline Journey — Type A e2e test.
 *
 * Runs a real info_gathering pipeline against testphp.vulnweb.com and verifies
 * the dashboard updates in real-time via SSE, then shows findings afterward.
 *
 * Timeout: 15 minutes. Requires full stack with workers running.
 */
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";

test.describe("Live Pipeline Journey", () => {
  test.setTimeout(900_000); // 15 min — real tools are slow

  const targetIds: number[] = [];

  test.afterAll(async () => {
    for (const id of targetIds) await apiClient.deleteTarget(id).catch(() => {});
  });

  test("info_gathering: C2 console shows running worker, assets appear after completion", async ({
    page,
  }) => {
    await apiClient.killAll().catch(() => {});

    const res = await apiClient.createTarget({
      company_name: "E2E-LivePipeline",
      base_domain: "testphp.vulnweb.com",
      playbook: "e2e_info_gathering",
    });
    targetIds.push(res.target_id);

    // Navigate to dashboard root and pick the new target
    await page.goto("/");
    await page
      .getByRole("button", { name: /testphp\.vulnweb\.com/ })
      .click({ timeout: 15_000 });
    await page.waitForURL("**/campaign/c2");

    // C2 worker grid must be visible before pipeline starts
    await expect(page.getByTestId("c2-worker-grid")).toBeVisible({
      timeout: 15_000,
    });

    // Wait for the worker to appear as RUNNING in the grid (60s — well before first stage completes)
    await page.waitForFunction(
      () => {
        const grid = document.querySelector('[data-testid="c2-worker-grid"]');
        return grid?.textContent?.toLowerCase().includes("running");
      },
      { timeout: 60_000 },
    );

    // Phase pipeline should be visible and updating
    await expect(page.getByTestId("c2-phase-pipeline")).toBeVisible({
      timeout: 30_000,
    });

    // Wait for COMPLETED status in the worker grid (780s — fits within 900s test timeout)
    await page.waitForFunction(
      () => {
        const grid = document.querySelector('[data-testid="c2-worker-grid"]');
        return grid?.textContent?.toLowerCase().includes("completed");
      },
      { timeout: 780_000 },
    );

    // Navigate to assets and verify real findings were stored
    await page.getByRole("link", { name: /assets/i }).click();
    await page.waitForURL("**/campaign/assets", { timeout: 10_000 });

    const table = page.getByTestId("assets-table");
    await expect(table).toBeVisible({ timeout: 15_000 });
    // testphp.vulnweb.com exposes discoverable assets — at least one row must exist
    await expect(page.getByTestId("asset-row").first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("input_validation: vulnerabilities page shows real findings after pipeline", async ({
    page,
  }) => {
    await apiClient.killAll().catch(() => {});

    const res = await apiClient.createTarget({
      company_name: "E2E-LiveVulns",
      base_domain: "testphp.vulnweb.com",
      playbook: "e2e_input_validation",
    });
    targetIds.push(res.target_id);

    await page.goto("/");
    await page
      .getByRole("button", { name: /testphp\.vulnweb\.com/ })
      .click({ timeout: 15_000 });
    await page.waitForURL("**/campaign/c2");

    // Wait for COMPLETED (780s — fits within 900s test timeout with room for navigation)
    await page.waitForFunction(
      () => {
        const grid = document.querySelector('[data-testid="c2-worker-grid"]');
        return grid?.textContent?.toLowerCase().includes("completed");
      },
      { timeout: 780_000 },
    );

    // Navigate to findings
    await page.getByRole("link", { name: /findings/i }).click();
    await page.waitForURL("**/campaign/findings", { timeout: 10_000 });

    // testphp.vulnweb.com has known SQLi and XSS — at least one finding must appear
    await expect(page.getByTestId("finding-row").first()).toBeVisible({
      timeout: 15_000,
    });
  });
});
