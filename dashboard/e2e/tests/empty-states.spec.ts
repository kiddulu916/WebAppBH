import { test, expect } from "../helpers/fixtures";
import { apiClient } from "../helpers/api-client";
import { factories } from "../helpers/seed-factories";

test.describe("Empty States", () => {
  let targetId: number;
  let baseDomain: string;

  // Create target but do NOT seed data — pages should show empty states
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

  test("assets page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Assets" }).click();
    await expect(page.getByTestId("assets-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("findings page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Findings" }).click();
    await expect(page.getByTestId("findings-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("bounties page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Bounties" }).click();
    await expect(page.getByTestId("bounties-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("schedules page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Schedules" }).click();
    await expect(page.getByTestId("schedules-empty-state")).toBeVisible({ timeout: 10_000 });
  });

  test("flow page shows empty config and monitor states", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Phase Flow" }).click();
    // Config side should show empty state (no playbook selected by user)
    await expect(page.getByTestId("flow-empty-config")).toBeVisible({ timeout: 10_000 });
    // Monitor may show execution stages (createTarget auto-starts a job)
    // so accept either empty-monitor or actual monitor stage entries
    await expect(
      page.getByTestId("flow-empty-monitor")
        .or(page.getByTestId("flow-monitor-stage-enumerate_subdomains"))
    ).toBeVisible({ timeout: 5_000 });
  });

  test("graph page shows empty state", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: new RegExp(baseDomain) }).click();
    await page.waitForURL("**/campaign/c2");
    await page.getByRole("link", { name: "Attack Graph" }).click();
    await expect(page.getByTestId("graph-empty-state")).toBeVisible({ timeout: 10_000 });
  });
});
