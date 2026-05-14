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
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: {
          args: ["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"],
        },
      },
    },
  ],

  reporter: [["html", { open: "never" }], ["list"]],
});
