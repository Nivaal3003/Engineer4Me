import type { ProtectedCapabilityId } from "../capabilities";
import { validateFieldInteractionIdentifier } from "./models";

export const FIELD_INTERACTION_INTENT_KINDS = [
  "query",
  "command",
  "undetermined",
] as const;

export type FieldInteractionIntentKind =
  (typeof FIELD_INTERACTION_INTENT_KINDS)[number];

export type FieldInteractionAuthorizationBoundary =
  | "review_required_before_query_preparation"
  | "explicit_command_authorization_required"
  | "intent_clarification_required";

export interface ControlledIntentProposal {
  readonly proposalId: string;
  readonly capabilityId: ProtectedCapabilityId;
  readonly intentKind: FieldInteractionIntentKind;
  readonly normalizedPrompt: string;
  readonly candidateOperationKey: null;
  readonly authorizationBoundary: FieldInteractionAuthorizationBoundary;
  readonly requiresUserReview: true;
  readonly executionAuthorized: false;
  readonly backendRequestPrepared: false;
  readonly bearerTokenAttached: false;
  readonly protectedContentLoaded: false;
  readonly automaticBestBrandSelection: false;
  readonly standardsConformityClaimed: false;
  readonly evidenceRequired: true;
}

function normalizePrompt(value: string): string {
  const normalized = value.trim().replace(/\s+/g, " ");
  if (normalized.length === 0) {
    throw new Error("Intent prompt is required.");
  }
  if (normalized.length > 4096) {
    throw new Error("Intent prompt exceeds 4096 characters.");
  }
  return normalized;
}

function authorizationBoundary(
  intentKind: FieldInteractionIntentKind,
): FieldInteractionAuthorizationBoundary {
  if (intentKind === "query") {
    return "review_required_before_query_preparation";
  }
  if (intentKind === "command") {
    return "explicit_command_authorization_required";
  }
  return "intent_clarification_required";
}

export function createControlledIntentProposal(input: {
  readonly proposalId: string;
  readonly capabilityId: ProtectedCapabilityId;
  readonly intentKind: FieldInteractionIntentKind;
  readonly prompt: string;
}): ControlledIntentProposal {
  return Object.freeze({
    proposalId: validateFieldInteractionIdentifier(
      input.proposalId,
      "Intent proposal identifier",
    ),
    capabilityId: input.capabilityId,
    intentKind: input.intentKind,
    normalizedPrompt: normalizePrompt(input.prompt),
    candidateOperationKey: null,
    authorizationBoundary: authorizationBoundary(input.intentKind),
    requiresUserReview: true,
    executionAuthorized: false,
    backendRequestPrepared: false,
    bearerTokenAttached: false,
    protectedContentLoaded: false,
    automaticBestBrandSelection: false,
    standardsConformityClaimed: false,
    evidenceRequired: true,
  });
}
