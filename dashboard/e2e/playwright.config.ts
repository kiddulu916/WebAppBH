import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  timeout: 30_000,
  retries: 1,
  workers: 1,
  fullyParallel: false,

  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },

  projects: [
    {
      // Standard suite: seeded-data tests, fast, runs in CI by default
      name: "chromium",
      testIgnore: ["**/flows/live-*.spec.ts"],
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: {
          args: ["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"],
        },
      },
    },
    {
      // Live-pipeline suite: real tool execution against testphp.vulnweb.com.
      // Run explicitly with: npx playwright test --project=live
      name: "live",
      testMatch: ["**/flows/live-*.spec.ts"],
      use: {
        ...devices["Desktop Chrome"],
        actionTimeout: 900_000,
        launchOptions: {
          args: ["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"],
        },
      },
    },
  ],

  reporter: [["html", { open: "never" }], ["list"]],
});
