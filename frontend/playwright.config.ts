import { defineConfig } from "@playwright/test";

const discoveryOnly = process.env.E4M_PLAYWRIGHT_DISCOVERY_ONLY === "1";

export default defineConfig({
  testDir: "./e2e",
  forbidOnly: true,
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: [["line"]],
  use: {
    baseURL: "http://127.0.0.1:4173",
    serviceWorkers: "block",
    trace: "retain-on-failure",
  },
  webServer: discoveryOnly
    ? undefined
    : {
        command:
          "npm run build && npm exec -- vite preview --host 127.0.0.1 --port 4173",
        url: "http://127.0.0.1:4173",
        reuseExistingServer: false,
      },
});
