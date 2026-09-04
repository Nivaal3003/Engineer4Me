import { validateFieldInteractionIdentifier } from "./models";

export const MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION =
  "phase10-microphone-permission-consent-v1" as const;
export const MICROPHONE_PERMISSION_CONSENT_DISCLOSURE =
  "Engineer4Me will ask the browser for microphone access only after you activate the reviewed control. The request is limited to microphone permission. It does not start capture, enumerate devices, read device identifiers, store audio, send data, authenticate, access protected content, or call an external service." as const;
export const MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256 =
  "b25091c17ab28b028c51e1a9f532febec810a1f2cfc95cad15688b9962d8e4bc" as const;
export const MICROPHONE_PERMISSION_PURPOSE =
  "prepare one future user-initiated microphone permission prompt" as const;

export type PermissionConsentDecision =
  | "not_recorded"
  | "affirmative"
  | "declined"
  | "withdrawn";

export interface PermissionConsentEvidence {
  readonly evidenceId: string;
  readonly permission: "microphone";
  readonly disclosureVersion:
    typeof MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION;
  readonly disclosureSha256:
    typeof MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256;
  readonly purpose: typeof MICROPHONE_PERMISSION_PURPOSE;
  readonly decision: PermissionConsentDecision;
  readonly occurredAtEpochMs: number | null;
  readonly explicit: boolean;
  readonly userInitiated: boolean;
  readonly importedFromControlledEvidence: boolean;
  readonly evidenceConsumed: false;
  readonly permissionPromptShownByThisRuntime: false;
  readonly browserPermissionApiCalledByThisRuntime: false;
  readonly captureStartedByThisRuntime: false;
}

function validEpochMs(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("Consent timestamp must be a non-negative safe integer.");
  }
  return value;
}

export function createUnrecordedMicrophonePermissionConsent():
  PermissionConsentEvidence {
  return Object.freeze({
    evidenceId: "microphone-consent-not-recorded",
    permission: "microphone",
    disclosureVersion: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
    disclosureSha256: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
    purpose: MICROPHONE_PERMISSION_PURPOSE,
    decision: "not_recorded",
    occurredAtEpochMs: null,
    explicit: false,
    userInitiated: false,
    importedFromControlledEvidence: false,
    evidenceConsumed: false,
    permissionPromptShownByThisRuntime: false,
    browserPermissionApiCalledByThisRuntime: false,
    captureStartedByThisRuntime: false,
  });
}

export function createImportedMicrophonePermissionConsent(input: {
  readonly evidenceId: string;
  readonly disclosureVersion: string;
  readonly disclosureSha256: string;
  readonly purpose: string;
  readonly decision: Exclude<PermissionConsentDecision, "not_recorded">;
  readonly occurredAtEpochMs: number;
  readonly explicit: boolean;
  readonly userInitiated: boolean;
}): PermissionConsentEvidence {
  if (input.disclosureVersion !== MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION) {
    throw new Error("Consent disclosure version differs from the reviewed version.");
  }
  if (input.disclosureSha256 !== MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256) {
    throw new Error("Consent disclosure integrity differs from the reviewed text.");
  }
  if (input.purpose !== MICROPHONE_PERMISSION_PURPOSE) {
    throw new Error("Consent purpose differs from the reviewed purpose limitation.");
  }
  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "Permission-consent evidence identifier",
    ),
    permission: "microphone",
    disclosureVersion: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_VERSION,
    disclosureSha256: MICROPHONE_PERMISSION_CONSENT_DISCLOSURE_SHA256,
    purpose: MICROPHONE_PERMISSION_PURPOSE,
    decision: input.decision,
    occurredAtEpochMs: validEpochMs(input.occurredAtEpochMs),
    explicit: input.explicit,
    userInitiated: input.userInitiated,
    importedFromControlledEvidence: true,
    evidenceConsumed: false,
    permissionPromptShownByThisRuntime: false,
    browserPermissionApiCalledByThisRuntime: false,
    captureStartedByThisRuntime: false,
  });
}
