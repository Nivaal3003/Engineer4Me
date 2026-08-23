import { expect, test } from "@playwright/test";

test("renders the inactive Engineer4Me security bootstrap", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Frontend security bootstrap" }),
  ).toBeVisible();
  await expect(page.getByText("Authentication activation")).toBeVisible();
  await expect(page.getByText("Blocked")).toBeVisible();
});
