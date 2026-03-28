import { test as base, expect } from "@playwright/test";

/**
 * Extended test fixture that dismisses the onboarding tour
 * by pre-setting localStorage before each page navigation.
 */
export const test = base.extend({
  page: async ({ page }, use) => {
    await page.addInitScript(() => {
      localStorage.setItem(
        "webbh-ui",
        JSON.stringify({
          state: { dockExpanded: false, hasSeenTour: true },
          version: 0,
        }),
      );
    });
    await use(page);
  },
});

export { expect };
