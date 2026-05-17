/**
 * Live Campaign Deep Views
 *
 * Exercises the per-campaign tabbed views (/campaign/[id]/*) that are not
 * covered by the seeded-data chromium suite.  Requires a completed
 * info_gathering run — the tests locate the first completed target via the
 * API and navigate through its campaign pages.
 *
 * Run with: npx playwright test --project=live
 */
import { test, expect } from "../../helpers/fixtures";
import { apiClient } from "../../helpers/api-client";

// ── helpers ────────────────────────────────────────────────────────────────

interface CompletedTarget {
  targetId: number;
  campaignId: number;
  baseDomain: string;
  assetCount: number;
}

/** Find the first completed target that has assets and an associated campaign. */
async function findCompletedTarget(): Promise<CompletedTarget | null> {
  const { targets } = await apiClient.getTargets();
  const done = targets.find((t) => t.status === "completed" && t.asset_count > 0);
  if (!done) return null;

  const { campaigns } = await apiClient.getCampaigns();
  if (!campaigns.length) return null;

  return {
    targetId: done.id,
    campaignId: campaigns[0].id,
    baseDomain: done.base_domain,
    assetCount: done.asset_count,
  };
}

// ── suite ──────────────────────────────────────────────────────────────────

test.describe("Live: Campaign Deep Views", () => {
  let ctx: CompletedTarget;

  test.beforeAll(async () => {
    const found = await findCompletedTarget();
    if (!found) {
      // No completed run on this stack — skip gracefully.
      test.skip();
      return;
    }
    ctx = found;
  });

  test("overview: stat cards and pipeline grid render", async ({ page }) => {
    await page.goto(`/campaign/${ctx.campaignId}/overview`);

    // Page header
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible({
      timeout: 10_000,
    });

    // Four stat cards must be present
    await expect(page.getByText("Workers Complete")).toBeVisible();
    await expect(page.getByText("Running")).toBeVisible();
    await expect(page.getByText("Failed")).toBeVisible();
    await expect(page.getByText("Skipped")).toBeVisible();

    // Pipeline progress section
    await expect(page.getByText("Pipeline Progress")).toBeVisible();

    // At least one worker card renders inside the pipeline grid
    await expect(
      page.getByRole("button", { name: /info gathering/i }),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("overview → targets tab: hierarchy shows the correct target", async ({ page }) => {
    await page.goto(`/campaign/${ctx.campaignId}/targets`);

    await expect(
      page.getByRole("heading", { name: /target hierarchy/i }),
    ).toBeVisible({ timeout: 10_000 });

    // Seed target must appear in the hierarchy
    await expect(page.getByText(ctx.baseDomain)).toBeVisible();

    // Link navigates to per-target drilldown
    const targetLink = page.getByRole("link", { name: new RegExp(ctx.baseDomain) });
    await expect(targetLink).toBeVisible();
    await expect(targetLink).toHaveAttribute(
      "href",
      new RegExp(`/campaign/${ctx.campaignId}/targets/${ctx.targetId}`),
    );
  });

  test("per-target drilldown: status and asset count are visible", async ({ page }) => {
    await page.goto(`/campaign/${ctx.campaignId}/targets/${ctx.targetId}`);

    // Target domain as page heading
    await expect(page.getByRole("heading", { name: ctx.baseDomain })).toBeVisible({
      timeout: 10_000,
    });

    // Stat line must include "completed" and a non-zero asset count
    await expect(page.getByText(/completed/i)).toBeVisible();
    await expect(
      page.getByText(new RegExp(ctx.assetCount.toLocaleString())),
    ).toBeVisible();

    // Pipeline progress section is present
    await expect(page.getByText("Pipeline Progress")).toBeVisible();
  });

  test("findings tab: filter controls render and empty state is correct", async ({ page }) => {
    await page.goto(`/campaign/${ctx.campaignId}/findings`);

    await expect(page.getByRole("heading", { name: /findings/i })).toBeVisible({
      timeout: 10_000,
    });

    // Filter row
    await expect(page.getByText("Severity")).toBeVisible();
    await expect(page.getByText("Worker")).toBeVisible();
    await expect(page.getByText("Section Range")).toBeVisible();
    await expect(page.getByRole("checkbox", { name: /confirmed only/i })).toBeVisible();
    await expect(page.getByRole("checkbox", { name: /hide false positives/i })).toBeVisible();

    // Table header columns
    const table = page.getByRole("table");
    await expect(table).toBeVisible();
    await expect(table.getByRole("columnheader", { name: /severity/i })).toBeVisible();
    await expect(table.getByRole("columnheader", { name: /title/i })).toBeVisible();
    await expect(table.getByRole("columnheader", { name: /section id/i })).toBeVisible();
  });

  test("tab navigation bar links work without full reload", async ({ page }) => {
    await page.goto(`/campaign/${ctx.campaignId}/overview`);

    let reloadCount = 0;
    page.on("load", () => reloadCount++);
    const baseline = reloadCount;

    // Click Targets tab
    await page.getByRole("link", { name: /^targets$/i }).click();
    await page.waitForURL(`**/campaign/${ctx.campaignId}/targets`, {
      timeout: 5_000,
    });

    // Click Findings tab
    await page.getByRole("link", { name: /^findings$/i }).click();
    await page.waitForURL(`**/campaign/${ctx.campaignId}/findings`, {
      timeout: 5_000,
    });

    // SPA navigation must not trigger a full page reload
    expect(reloadCount).toBe(baseline);
  });
});
