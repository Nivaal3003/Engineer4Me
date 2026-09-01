import {
  DESIGN_TOKENS,
  DESIGN_TOKEN_VERSION,
  isStrictlyIncreasing,
} from "./tokens";

describe("Engineer4Me design tokens", () => {
  it("retains the 44 pixel product interaction target", () => {
    expect(DESIGN_TOKEN_VERSION).toBe("phase9-step295-v1");
    expect(DESIGN_TOKENS.interaction.minimumTargetPx).toBe(44);
  });

  it("uses ordered spacing, breakpoint, and typography scales", () => {
    expect(isStrictlyIncreasing(DESIGN_TOKENS.spacingPx)).toBe(true);
    expect(
      isStrictlyIncreasing(Object.values(DESIGN_TOKENS.breakpoints)),
    ).toBe(true);
    expect(
      isStrictlyIncreasing(Object.values(DESIGN_TOKENS.typographyRem)),
    ).toBe(true);
  });
});
