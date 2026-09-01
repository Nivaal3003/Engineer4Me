import {
  IDENTIFIER_MAX_LENGTH,
  InvalidEngineeringIdentifierError,
  engineeringIdentifierValue,
  parseEngineeringIdentifier,
} from "./identifiers";

describe("engineering identifiers", () => {
  it("accepts bounded traceable identifiers", () => {
    const identifier = parseEngineeringIdentifier("design case", "design:case-001");
    expect(engineeringIdentifierValue(identifier)).toBe("design:case-001");
  });

  it("rejects path separators, whitespace, and oversized values", () => {
    expect(() => parseEngineeringIdentifier("record", "../record")).toThrow(
      InvalidEngineeringIdentifierError,
    );
    expect(() => parseEngineeringIdentifier("record", "record one")).toThrow(
      InvalidEngineeringIdentifierError,
    );
    expect(() =>
      parseEngineeringIdentifier("record", "a".repeat(IDENTIFIER_MAX_LENGTH + 1)),
    ).toThrow(InvalidEngineeringIdentifierError);
  });
});
