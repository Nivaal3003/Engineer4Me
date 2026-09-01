import { createCorrelationId, validateCorrelationId } from "./correlation";

describe("correlation identifiers", () => {
  it("creates a deterministic controlled identifier from injected entropy", () => {
    expect(createCorrelationId(() => new Uint8Array(16).fill(10))).toBe(
      "e4m-0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
    );
  });

  it("rejects unsafe values and invalid entropy lengths", () => {
    expect(() => validateCorrelationId("short")).toThrow();
    expect(() => validateCorrelationId("invalid value")).toThrow();
    expect(() => createCorrelationId(() => new Uint8Array(15))).toThrow();
  });
});
