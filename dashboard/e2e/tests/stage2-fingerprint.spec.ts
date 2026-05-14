import { test, expect } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

// ─── shared mocks ────────────────────────────────────────────────────

const BASE_TARGET = {
  id: 1,
  base_domain: "fp-test.example.com",
  company_name: "FP Test Corp",
  target_profile: null,
  last_playbook: "wide_recon",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const SUMMARY_OBS = {
  id: 9001,
  tech_stack: {
    _probe: "summary",
    intensity: "high",
    partial: false,
    fingerprint: {
      edge: { vendor: "cloudflare", confidence: 0.97, signals: [], conflict: false },
      origin_server: { vendor: "nginx/1.24.0", confidence: 0.85, signals: [], conflict: false },
      framework: { vendor: null, confidence: 0, signals: [], conflict: false },
      waf: { vendor: "Cloudflare", confidence: 0.98, signals: [], conflict: false },
      tls: { tls_version: "TLSv1.3", cert_issuer: "Cloudflare Inc" },
    },
  },
};

function makeAssetsResponse(observations: typeof SUMMARY_OBS[]) {
  return {
    total: 1,
    page: 1,
    page_size: 50,
    assets: [
      {
        id: 42,
        target_id: 1,
        asset_type: "subdomain",
        asset_value: "api.fp-test.example.com",
        source_tool: "stage2",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        tech: null,
        scope_classification: "in_scope",
        associated_with_id: null,
        association_method: null,
        locations: [],
        observations,
      },
    ],
  };
}

// ─── helpers ─────────────────────────────────────────────────────────

async function navigateToPlaybookStep(page: Page) {
  await page.goto("/campaign");
  await expect(page.getByTestId("scope-builder")).toBeVisible({ timeout: 10_000 });
  await page.getByTestId("scope-company-input").fill("FP Test Corp");
  await page.getByTestId("scope-domain-input").fill("fp-test.example.com");
  await page.getByTestId("scope-next-btn").click();
  await expect(page.getByTestId("scope-step-1")).toBeVisible();
  await page.getByTestId("scope-next-btn").click();
  await expect(
    page.getByRole("button", { name: /Create Custom Playbook/i }),
  ).toBeVisible({ timeout: 5_000 });
}

async function setupC2Page(page: Page, observations: typeof SUMMARY_OBS[]) {
  await page.addInitScript((target: typeof BASE_TARGET) => {
    localStorage.setItem(
      "webbh-campaign",
      JSON.stringify({
        state: { activeTarget: target, currentPhase: null },
        version: 0,
      }),
    );
  }, BASE_TARGET);

  const assetsResponse = makeAssetsResponse(observations);

  await page.route("**/api/v1/assets**", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify(assetsResponse),
    }),
  );
  await page.route("**/api/v1/status**", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ jobs: [] }),
    }),
  );
  await page.route("**/api/v1/queue_health**", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ queues: {} }),
    }),
  );

  await page.goto("/campaign/c2");
  await expect(page.getByTestId("c2-asset-tree")).toBeVisible({ timeout: 10_000 });
}

// ─── PlaybookEditor intensity selector ───────────────────────────────

test.describe("Stage 2 Fingerprint — PlaybookEditor intensity selector", () => {
  test("E1: renders 3 intensity radio buttons when info_gathering worker expanded", async ({
    page,
  }) => {
    await navigateToPlaybookStep(page);
    await page.getByRole("button", { name: /Create Custom Playbook/i }).click();
    await page.getByTestId("worker-expand-info_gathering").click();
    await expect(page.getByTestId("fp-intensity-selector")).toBeVisible({
      timeout: 5_000,
    });
    await expect(
      page.getByTestId("fp-intensity-selector").getByRole("radio"),
    ).toHaveCount(3);
  });

  test("E2: default intensity selection is low", async ({ page }) => {
    await navigateToPlaybookStep(page);
    await page.getByRole("button", { name: /Create Custom Playbook/i }).click();
    await page.getByTestId("worker-expand-info_gathering").click();
    await expect(page.getByTestId("fp-intensity-selector")).toBeVisible({
      timeout: 5_000,
    });
    await expect(
      page
        .getByTestId("fp-intensity-selector")
        .getByRole("radio", { name: /low/i }),
    ).toBeChecked();
  });

  test("E8: selecting medium shows PROPFIND warning; selecting high shows malformed warning", async ({
    page,
  }) => {
    await navigateToPlaybookStep(page);
    await page.getByRole("button", { name: /Create Custom Playbook/i }).click();
    await page.getByTestId("worker-expand-info_gathering").click();
    await expect(page.getByTestId("fp-intensity-selector")).toBeVisible({
      timeout: 5_000,
    });
    await page
      .getByTestId("fp-intensity-selector")
      .getByRole("radio", { name: /medium/i })
      .click();
    await expect(page.getByText(/PROPFIND/)).toBeVisible();
    await page
      .getByTestId("fp-intensity-selector")
      .getByRole("radio", { name: /high/i })
      .click();
    await expect(page.getByText(/malformed/)).toBeVisible();
  });
});

// ─── FingerprintPanel in AssetDetailDrawer ───────────────────────────

test.describe("Stage 2 Fingerprint — FingerprintPanel in AssetDetailDrawer", () => {
  test("E3: FingerprintPanel renders when summary observation is present", async ({
    page,
  }) => {
    await setupC2Page(page, [SUMMARY_OBS]);
    await page
      .getByTestId("c2-asset-tree")
      .getByRole("button", { name: "api.fp-test.example.com" })
      .click();
    await expect(page.getByTestId("fingerprint-panel")).toBeVisible({
      timeout: 5_000,
    });
  });

  test("E4: FingerprintPanel shows cloudflare in edge and waf slots", async ({
    page,
  }) => {
    await setupC2Page(page, [SUMMARY_OBS]);
    await page
      .getByTestId("c2-asset-tree")
      .getByRole("button", { name: "api.fp-test.example.com" })
      .click();
    await expect(page.getByTestId("fingerprint-panel")).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId("slot-edge")).toContainText("cloudflare");
    await expect(page.getByTestId("slot-waf")).toContainText("Cloudflare");
  });

  test("E5: FingerprintPanel shows intensity badge", async ({ page }) => {
    await setupC2Page(page, [SUMMARY_OBS]);
    await page
      .getByTestId("c2-asset-tree")
      .getByRole("button", { name: "api.fp-test.example.com" })
      .click();
    await expect(page.getByTestId("fingerprint-panel")).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId("fingerprint-panel")).toContainText("high");
  });

  test("E6: FingerprintPanel shows partial badge when partial is true", async ({
    page,
  }) => {
    const partialObs = {
      ...SUMMARY_OBS,
      tech_stack: { ...SUMMARY_OBS.tech_stack, partial: true },
    };
    await setupC2Page(page, [partialObs]);
    await page
      .getByTestId("c2-asset-tree")
      .getByRole("button", { name: "api.fp-test.example.com" })
      .click();
    await expect(page.getByTestId("fingerprint-panel")).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId("fingerprint-panel")).toContainText("partial");
  });

  test("E7: FingerprintPanel is absent when asset has no summary observation", async ({
    page,
  }) => {
    await setupC2Page(page, []);
    await page
      .getByTestId("c2-asset-tree")
      .getByRole("button", { name: "api.fp-test.example.com" })
      .click();
    await expect(page.getByText("ASSET DETAILS")).toBeVisible({ timeout: 5_000 });
    await expect(page.getByTestId("fingerprint-panel")).not.toBeVisible();
  });
});
