import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "./tests/browser",
  use: {
    baseURL: "http://127.0.0.1:4177/payload-clinic/",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev -- --port 4177 --strictPort",
    url: "http://127.0.0.1:4177/payload-clinic/",
    reuseExistingServer: false,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
