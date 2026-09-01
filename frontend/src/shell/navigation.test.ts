import { navigationItemByPath, SHELL_NAVIGATION_ITEMS } from "./navigation";

describe("Engineer4Me product-shell route navigation", () => {
  it("preserves all capability areas as unique controlled browser paths", () => {
    expect(SHELL_NAVIGATION_ITEMS).toHaveLength(9);
    expect(new Set(SHELL_NAVIGATION_ITEMS.map((item) => item.path)).size).toBe(9);
    expect(SHELL_NAVIGATION_ITEMS.filter((item) => item.state === "available")).toEqual([
      expect.objectContaining({ id: "home", path: "/" }),
    ]);
  });

  it("labels protected, entitled, and controlled destinations explicitly", () => {
    expect(navigationItemByPath("/selection")).toMatchObject({ stateLabel: "Protected" });
    expect(navigationItemByPath("/design-cases")).toMatchObject({ stateLabel: "Entitled" });
    expect(navigationItemByPath("/access-audit")).toMatchObject({ stateLabel: "Controlled" });
    expect(navigationItemByPath("/missing")).toBeNull();
  });
});
