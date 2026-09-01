import { MINIMUM_PRODUCT_INTERACTION_TARGET_PX } from "../foundation";

export const DESIGN_TOKEN_VERSION = "phase9-step295-v1" as const;

export const DESIGN_TOKENS = Object.freeze({
  interaction: Object.freeze({
    minimumTargetPx: MINIMUM_PRODUCT_INTERACTION_TARGET_PX,
    focusRingWidthPx: 3,
    focusRingOffsetPx: 3,
  }),
  breakpoints: Object.freeze({
    compactPx: 480,
    navigationPx: 900,
    widePx: 1180,
  }),
  spacingPx: Object.freeze([0, 4, 8, 12, 16, 24, 32, 48, 64] as const),
  radiusPx: Object.freeze({
    control: 10,
    card: 16,
    panel: 22,
    pill: 999,
  }),
  typographyRem: Object.freeze({
    caption: 0.75,
    bodySmall: 0.875,
    body: 1,
    titleSmall: 1.125,
    title: 1.5,
    display: 2.25,
  }),
  contentWidthRem: Object.freeze({
    reading: 46,
    workspace: 88,
  }),
});

export type DesignTokens = typeof DESIGN_TOKENS;

export function isStrictlyIncreasing(values: readonly number[]): boolean {
  return values.every((value, index) => index === 0 || value > values[index - 1]);
}
