import { expect, test } from "@playwright/test";
import { installE2eNetworkControl } from "./network-control";

test.beforeEach(async ({ page }) => {
  await installE2eNetworkControl(page);
});

test("renders the inactive Engineer4Me mobile-first product shell", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", {
      name: "Engineering decisions, with evidence visible",
    }),
  ).toBeVisible();
  await expect(page.getByText("Authentication activation")).toBeVisible();
  await expect(page.getByText("API transport")).toBeVisible();
  await expect(page.getByText("No standards conformity claim")).toBeVisible();
  await expect(page.getByRole("button", { name: /sign in/i })).toHaveCount(0);
});
