import { BACKEND_OPERATIONS, getBackendOperation } from "./operation-registry";

describe("accepted backend operation registry", () => {
  it("contains the exact 93-operation Step 281 static inventory", () => {
    expect(BACKEND_OPERATIONS).toHaveLength(93);
    expect(new Set(BACKEND_OPERATIONS.map(({ key }) => key)).size).toBe(93);
    expect(
      BACKEND_OPERATIONS.filter(({ frontendAccessPolicy }) =>
        frontendAccessPolicy === "public",
      ).map(({ pathTemplate }) => pathTemplate),
    ).toEqual(["/", "/health"]);
  });

  it("keeps all operation paths same-origin relative and source-traceable", () => {
    for (const operation of BACKEND_OPERATIONS) {
      expect(operation.pathTemplate.startsWith("/")).toBe(true);
      expect(operation.pathTemplate).not.toContain("://");
      expect(operation.pathTemplate).not.toContain("?");
      expect(operation.pathTemplate).not.toContain("#");
      expect(operation.source.startsWith("backend/app/")).toBe(true);
      expect(operation.sourceLine).toBeGreaterThan(0);
    }
  });

  it("fails closed for an operation absent from the accepted inventory", () => {
    expect(() => getBackendOperation("not_registered")).toThrow(
      "Unknown Engineer4Me backend operation",
    );
  });
});
