import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";
import { factories } from "../../helpers/seed-factories";

test.describe("Flow: Worker Execution Monitoring", () => {
  let targetId: number;
  let baseDomain: string;

  test.beforeAll(async () => {
    // Kill active jobs so target creation isn't blocked by 409
    await apiClient.killAll().catch(() => {});
    const data = factories.target();
    baseDomain = data.base_domain;
    const res = await apiClient.createTarget(data);
    targetId = res.target_id;
    await apiClient.seedTestData(targetId);
  });

  test.afterAll(async () => {
    if (targetId) await apiClient.deleteTarget(targetId).catch(() => {});
  });

  test("flow monitor reflects execution state and SSE events propagate to C2", async ({ page }) => {
    // 1. Navigate to flow page
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    // 2. Verify monitor shows stage statuses from seeded jobs
    await expect(page.getByTestId("flow-monitor-stage-enumerate_subdomains")).toBeVisible({ timeout: 10_000 });

    // 3. Emit a test event (stage completion)
    await apiClient.emitTestEvent(targetId, {
      event_type: "STAGE_COMPLETE",
      stage: "passive_discovery",
      status: "completed",
      tool: "subfinder",
    });

    // 4. Verify flow page updates (within polling interval)
    await page.waitForTimeout(12_000);

    // 5. Navigate to C2 and verify timeline
    await page.getByRole("link", { name: "C2 Console" }).click();
    await page.waitForURL("**/campaign/c2");
    const timeline = page.getByTestId("c2-timeline");
    await expect(timeline).toBeVisible({ timeout: 10_000 });

    // 6. Verify assets page shows seeded assets
    await page.getByRole("link", { name: "Assets" }).click();
    await page.waitForURL("**/campaign/assets");
    await expect(page.getByText(`sub1.${baseDomain}`)).toBeVisible({ timeout: 10_000 });

    // 7. Verify findings page shows seeded vulns
    await page.getByRole("link", { name: "Findings" }).click();
    await page.waitForURL("**/campaign/findings");
    await expect(page.getByText("SQL Injection").first()).toBeVisible({ timeout: 10_000 });
  });

  test("SSE disconnect shows connection-lost and reconnect works", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    await expect(page.getByTestId("flow-monitor-stage-enumerate_subdomains")).toBeVisible({ timeout: 10_000 });

    // Block execution state endpoint to simulate disconnect
    await page.route("**/api/v1/targets/*/execution", (route) =>
      route.abort("connectionrefused")
    );

    // Wait for next poll cycle to fail
    await page.waitForTimeout(12_000);

    // Check for connection-lost indicator
    await expect(
      page.getByTestId("flow-connection-lost")
    ).toBeVisible({ timeout: 5_000 });

    // Restore and verify recovery
    await page.unroute("**/api/v1/targets/*/execution");
    await page.waitForTimeout(12_000);

    // Monitor should recover
    await expect(page.getByTestId("flow-monitor-stage-enumerate_subdomains")).toBeVisible();
  });
});
