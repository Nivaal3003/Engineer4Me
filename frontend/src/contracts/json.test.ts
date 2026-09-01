import { assertJsonValue, isJsonValue } from "./json";

describe("JSON boundary values", () => {
  it("accepts finite plain JSON values", () => {
    expect(isJsonValue({ value: 1, evidence: ["source"] })).toBe(true);
  });

  it("rejects non-finite and non-plain values", () => {
    expect(isJsonValue(Number.NaN)).toBe(false);
    expect(isJsonValue(new Date())).toBe(false);
    expect(() => assertJsonValue({ value: undefined })).toThrow(TypeError);
  });
});
