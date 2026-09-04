import { validateFieldInteractionIdentifier } from "./models";

export const MICROPHONE_PERMISSION_PROMPT_OUTCOMES = [
  "granted",
  "denied",
  "dismissed",
  "unavailable",
  "revoked",
] as const;

export type MicrophonePermissionPromptOutcome =
  (typeof MICROPHONE_PERMISSION_PROMPT_OUTCOMES)[number];

export interface ImportedMicrophonePermissionPromptOutcomeEvidence {
  readonly evidenceId: string;
  readonly source: "future_controlled_prompt_gate";
  readonly permission: "microphone";
  readonly outcome: MicrophonePermissionPromptOutcome;
  readonly promptCount: 1;
  readonly occurredAtEpochMs: number;
  readonly permissionStateQueried: false;
  readonly mediaDeviceEnumerationPerformed: false;
  readonly deviceIdentifierReadPerformed: false;
  readonly captureStarted: false;
  readonly rawMediaPersisted: false;
  readonly automaticRetryPerformed: false;
  readonly captureAuthorizationDerived: false;
  readonly furtherInterventionRequired: true;
}

export function createImportedMicrophonePermissionPromptOutcomeEvidence(input: {
  readonly evidenceId: string;
  readonly outcome: MicrophonePermissionPromptOutcome;
  readonly promptCount: number;
  readonly occurredAtEpochMs: number;
}): ImportedMicrophonePermissionPromptOutcomeEvidence {
  if (input.promptCount !== 1) {
    throw new Error("Imported permission prompt evidence must represent exactly one prompt.");
  }
  if (!Number.isSafeInteger(input.occurredAtEpochMs) || input.occurredAtEpochMs < 0) {
    throw new Error("Permission prompt outcome timestamp must be a non-negative safe integer.");
  }
  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "Permission prompt outcome evidence identifier",
    ),
    source: "future_controlled_prompt_gate",
    permission: "microphone",
    outcome: input.outcome,
    promptCount: 1,
    occurredAtEpochMs: input.occurredAtEpochMs,
    permissionStateQueried: false,
    mediaDeviceEnumerationPerformed: false,
    deviceIdentifierReadPerformed: false,
    captureStarted: false,
    rawMediaPersisted: false,
    automaticRetryPerformed: false,
    captureAuthorizationDerived: false,
    furtherInterventionRequired: true,
  });
}
