import { normalizeAccessValues, normalizeBoundedText, normalizeOpaqueIdentifier } from "./values";

describe("controlled authentication values", () => {
  it("deduplicates, lowercases, and sorts roles and entitlements", () => {
    expect(normalizeAccessValues(["Engineering.Read", "engineering.read", "Audit.View"], "entitlement"))
      .toEqual(["audit.view", "engineering.read"]);
  });

  it("rejects malformed or unbounded access values", () => {
    expect(() => normalizeAccessValues(["contains space"], "role")).toThrow(/controlled format/u);
    expect(() => normalizeAccessValues(new Array(129).fill("role"), "role")).toThrow(/Too many/u);
  });

  it("normalizes bounded display text and opaque identifiers", () => {
    expect(normalizeBoundedText("  Engineer Four  ", "name", 64)).toBe("Engineer Four");
    expect(normalizeOpaqueIdentifier("tenant:subject-1", "subject")).toBe("tenant:subject-1");
    expect(() => normalizeOpaqueIdentifier("subject with spaces", "subject")).toThrow();
  });
});
