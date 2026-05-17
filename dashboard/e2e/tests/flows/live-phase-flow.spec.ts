/**
 * Live Phase Flow
 *
 * Exercises the /campaign/flow page: execution monitor reflects a real
 * completed pipeline, the playbook selector is populated from the API, and
 * playbook configurator renders when a playbook is chosen.
 *
 * Run with: npx playwright test --project=live
 */
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";

test.describe("Live: Phase Flow Monitor", () => {
  let baseDomain: string;

  test.beforeAll(async () => {
    const { targets } = await apiClient.getTargets();
    const done = targets.find((t) => t.status === "completed" && t.asset_count > 0);
    if (!done) {
      test.skip();
      return;
    }
    baseDomain = done.base_domain;
  });

  test("execution monitor: Info Gathering shows COMPLETED after pipeline", async ({ page }) => {
    // Navigate to the flow page with the completed target selected via home
    await page.goto("/");
    await page
      .getByRole("button", { name: new RegExp(baseDomain) })
      .click({ timeout: 10_000 });
    await page.waitForURL("**/campaign/c2");

    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    // Execution monitor panel is visible
    await expect(page.getByText("Execution Monitor")).toBeVisible({
      timeout: 10_000,
    });

    // Info Gathering worker card in the monitor
    const infoGatheringCard = page.getByTestId("flow-monitor-worker-info_gathering");
    await expect(infoGatheringCard).toBeVisible({ timeout: 10_000 });

    // Its status must read COMPLETED (real pipeline result)
    await expect(infoGatheringCard).toContainText(/completed/i);
  });

  test("execution monitor: can expand a worker to reveal stage list", async ({ page }) => {
    await page.goto("/");
    await page
      .getByRole("button", { name: new RegExp(baseDomain) })
      .click({ timeout: 10_000 });
    await page.waitForURL("**/campaign/c2");

    await page.getByRole("link", { name: "Phase Flow" }).click();
    await page.waitForURL("**/campaign/flow");

    const infoGatheringCard = page.getByTestId("flow-monitor-worker-info_gathering");
    await expect(infoGatheringCard).toBeVisible({ timeout: 10_000 });

    // Clicking the card expands it — stage rows appear
    await infoGatheringCard.click();

    // At least the last stage (map_application) must be visible after expansion
    await expect(
      page.getByTestId("flow-monitor-stage-map_application"),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("playbook configurator: select dropdown is populated with API playbooks", async ({ page }) => {
    await page.goto("/campaign/flow");

    const playbookSelect = page.getByTestId("flow-playbook-select");
    await expect(playbookSelect).toBeVisible({ timeout: 10_000 });

    // The select must contain at least one real playbook option
    const options = await playbookSelect.locator("option").all();
    expect(options.length).toBeGreaterThan(1); // first is placeholder
  });

  test("playbook configurator: selecting a playbook reveals worker/stage toggles", async ({ page }) => {
    await page.goto("/campaign/flow");

    const playbookSelect = page.getByTestId("flow-playbook-select");
    await expect(playbookSelect).toBeVisible({ timeout: 10_000 });

    // Empty state shows until a playbook is chosen
    await expect(page.getByTestId("flow-empty-config")).toBeVisible();

    // Pick the first real option (index 1 — skip the placeholder at 0)
    const options = await playbookSelect.locator("option").all();
    if (options.length > 1) {
      const firstValue = await options[1].getAttribute("value");
      if (firstValue) {
        await playbookSelect.selectOption(firstValue);
      }
    }

    // After selecting, worker cards should appear
    await expect(page.getByTestId("flow-empty-config")).not.toBeVisible({
      timeout: 5_000,
    });

    // At least the info_gathering worker card is present
    await expect(
      page.getByTestId("flow-worker-card-info_gathering"),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("playbook configurator: save button is visible and not disabled when playbook selected", async ({ page }) => {
    await page.goto("/campaign/flow");

    const playbookSelect = page.getByTestId("flow-playbook-select");
    await expect(playbookSelect).toBeVisible({ timeout: 10_000 });

    const options = await playbookSelect.locator("option").all();
    if (options.length > 1) {
      const firstValue = await options[1].getAttribute("value");
      if (firstValue) await playbookSelect.selectOption(firstValue);
    }

    const saveBtn = page.getByTestId("flow-save-playbook-btn");
    await expect(saveBtn).toBeVisible({ timeout: 5_000 });
    await expect(saveBtn).not.toBeDisabled();
  });
});
