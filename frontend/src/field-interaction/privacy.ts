export const FIELD_DATA_CLASSIFICATIONS = [
  "public",
  "internal",
  "confidential",
  "personal_data",
  "operationally_sensitive",
  "unknown",
] as const;

export type FieldDataClassification =
  (typeof FIELD_DATA_CLASSIFICATIONS)[number];

export interface FieldInteractionPrivacyEvaluation {
  readonly classification: FieldDataClassification;
  readonly retentionMode: "memory_only";
  readonly externalProcessingRequested: boolean;
  readonly externalProcessingAllowed: false;
  readonly persistenceAllowed: false;
  readonly rawMediaRetentionAllowed: false;
  readonly requiresExplicitUserConfirmation: true;
  readonly requiresDataOwnerReview: boolean;
  readonly blockingReasons: readonly string[];
}

export function evaluateFieldInteractionPrivacy(input: {
  readonly classification: FieldDataClassification;
  readonly externalProcessingRequested: boolean;
}): FieldInteractionPrivacyEvaluation {
  const blockingReasons = [
    "No accepted external speech, vision, OCR, or AI processing service is configured.",
    "No persistence or protected-content storage adapter is active.",
    "Microphone and camera capture remain behind an intervention-required gate.",
  ];
  if (input.classification === "unknown") {
    blockingReasons.push(
      "The content classification is unknown and must be reviewed before any activation.",
    );
  }
  if (input.externalProcessingRequested) {
    blockingReasons.push(
      "External processing was requested but has no accepted provider, privacy, consent, or transfer evidence.",
    );
  }
  return Object.freeze({
    classification: input.classification,
    retentionMode: "memory_only",
    externalProcessingRequested: input.externalProcessingRequested,
    externalProcessingAllowed: false,
    persistenceAllowed: false,
    rawMediaRetentionAllowed: false,
    requiresExplicitUserConfirmation: true,
    requiresDataOwnerReview: input.classification !== "public",
    blockingReasons: Object.freeze(blockingReasons),
  });
}
