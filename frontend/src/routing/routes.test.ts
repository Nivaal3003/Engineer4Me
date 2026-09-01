import {
  APP_ROUTES,
  isKnownAppPath,
  normalizeAppPath,
  routeById,
  routeByPath,
  routeDocumentTitle,
} from "./routes";

describe("Engineer4Me controlled route registry", () => {
  it("binds every capability area to one unique same-origin path", () => {
    expect(APP_ROUTES).toHaveLength(9);
    expect(new Set(APP_ROUTES.map((route) => route.id)).size).toBe(9);
    expect(new Set(APP_ROUTES.map((route) => route.path)).size).toBe(9);
    expect(APP_ROUTES.every((route) => route.path.startsWith("/"))).toBe(true);
    expect(APP_ROUTES.every((route) => !route.path.includes("://"))).toBe(true);
  });

  it("normalizes route paths without interpreting external URLs", () => {
    expect(normalizeAppPath("selection/")).toBe("/selection");
    expect(normalizeAppPath("//documents///?tab=recent#top")).toBe("/documents");
    expect(normalizeAppPath("/")).toBe("/");
  });

  it("resolves known paths and preserves unknown paths as not found", () => {
    expect(routeByPath("/calculations/")).toMatchObject({ id: "calculations" });
    expect(routeById("security")).toMatchObject({
      path: "/access-audit",
      accessRequirement: "controlled_administration",
    });
    expect(routeByPath("/not-a-route")).toBeNull();
    expect(isKnownAppPath("/not-a-route")).toBe(false);
    expect(routeDocumentTitle("/not-a-route")).toBe("Page not found — Engineer4Me");
  });
});
