import { expect, test } from "@playwright/test";
import { installE2eNetworkControl } from "./network-control";

test.beforeEach(async ({ page }) => {
  await installE2eNetworkControl(page);
});

test("renders the controlled Engineer4Me browser workspace", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Engineering decisions, with evidence visible" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Authentication and access status" })).toBeVisible();
  await expect(page.getByText("No remote audit records loaded")).toBeVisible();
  await expect(page.getByText("No standards conformity claim")).toBeVisible();
  await expect(page.getByRole("button", { name: /sign in/iu })).toHaveCount(0);
});

test("navigates to a fail-closed protected capability route", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("navigation", { name: "Desktop product navigation" }).getByRole("link", { name: "Selection & sizing" }).click();
  await expect(page).toHaveURL(/\/selection$/u);
  await expect(page.getByRole("heading", { name: "Selection & sizing is not available" })).toBeVisible();
  await expect(page.getByText(/Authentication is not active/)).toBeVisible();
});

test("renders the explicit not-found experience", async ({ page }) => {
  await page.goto("/unknown-engineering-view");
  await expect(page.getByRole("heading", { name: "The requested page does not exist" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Return to workspace" })).toBeVisible();
});
