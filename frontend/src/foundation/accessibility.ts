/**
 * Phase 9 accessibility invariants for the Engineer4Me browser product.
 *
 * This module contains product constraints only. It does not activate routing,
 * authentication, network access, service workers, or native packaging.
 */
export const ACCESSIBILITY_CONFORMANCE_TARGET = "WCAG 2.2 AA" as const;
export const MINIMUM_PRODUCT_INTERACTION_TARGET_PX = 44 as const;

export const ACCESSIBILITY_FOUNDATION = Object.freeze({
  conformanceTarget: ACCESSIBILITY_CONFORMANCE_TARGET,
  keyboardOperationRequired: true,
  screenReaderCompatibilityRequired: true,
  visibleFocusRequired: true,
  reducedMotionMustBeRespected: true,
  minimumInteractionTargetPx: MINIMUM_PRODUCT_INTERACTION_TARGET_PX,
  automatedChecksAreSufficientForApproval: false,
  manualReviewRequiredBeforePhaseClosure: true,
});

export type AccessibilityFoundation = typeof ACCESSIBILITY_FOUNDATION;
