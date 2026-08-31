import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["e2e/**", "dist/**", "**/node_modules/**", "**/.git/**"],
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    clearMocks: true,
    mockReset: true,
    restoreMocks: true,
    passWithNoTests: false,
  },
});
