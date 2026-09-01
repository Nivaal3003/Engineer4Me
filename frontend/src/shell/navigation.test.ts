import { currentNavigationItems, SHELL_NAVIGATION_ITEMS } from "./navigation";

describe("Engineer4Me product-shell navigation ownership", () => {
  it("preserves all capability areas without activating browser routes", () => {
    expect(SHELL_NAVIGATION_ITEMS).toHaveLength(9);
    expect(SHELL_NAVIGATION_ITEMS.every((item) => item.browserRouteActivation === "not_authorized_in_foundation")).toBe(true);
    expect(SHELL_NAVIGATION_ITEMS.filter((item) => item.inPageTarget !== null)).toHaveLength(1);
  });

  it("has exactly one current in-page destination", () => {
    expect(currentNavigationItems()).toEqual([
      expect.objectContaining({ id: "home", state: "current", inPageTarget: "#main-content" }),
    ]);
  });
});
