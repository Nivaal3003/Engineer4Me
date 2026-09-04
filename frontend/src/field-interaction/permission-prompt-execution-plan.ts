import type { MicrophonePermissionPromptProposal } from "./permission-prompt-proposal";

export interface MicrophonePermissionPromptExecutionPlan {
  readonly planType: "future_controlled_microphone_permission_prompt";
  readonly state: "evidence_incomplete" | "intervention_required";
  readonly proposalId: string;
  readonly permission: "microphone";
  readonly futureOperationName: "browser_microphone_permission_request";
  readonly exactPromptCountMaximum: 1;
  readonly explicitUserGestureRequired: true;
  readonly explicitConsentRequired: true;
  readonly singleUseEvidenceRequired: true;
  readonly automaticRetryAllowed: false;
  readonly cameraPermissionIncluded: false;
  readonly permissionStatusQueryIncluded: false;
  readonly mediaDeviceEnumerationIncluded: false;
  readonly captureIncluded: false;
  readonly externalNetworkIncluded: false;
  readonly authenticationIncluded: false;
  readonly backendTransportIncluded: false;
  readonly externalAiIncluded: false;
  readonly promptExecutionOperationAvailable: false;
  readonly executionAuthorized: false;
  readonly interventionRequired: true;
  readonly futureGateRequirements: readonly string[];
}

export function createMicrophonePermissionPromptExecutionPlan(
  proposal: MicrophonePermissionPromptProposal,
): MicrophonePermissionPromptExecutionPlan {
  const eligible = proposal.eligibleForPromptExecutionIntervention;
  return Object.freeze({
    planType: "future_controlled_microphone_permission_prompt",
    state: eligible ? "intervention_required" : "evidence_incomplete",
    proposalId: proposal.proposalId,
    permission: "microphone",
    futureOperationName: "browser_microphone_permission_request",
    exactPromptCountMaximum: 1,
    explicitUserGestureRequired: true,
    explicitConsentRequired: true,
    singleUseEvidenceRequired: true,
    automaticRetryAllowed: false,
    cameraPermissionIncluded: false,
    permissionStatusQueryIncluded: false,
    mediaDeviceEnumerationIncluded: false,
    captureIncluded: false,
    externalNetworkIncluded: false,
    authenticationIncluded: false,
    backendTransportIncluded: false,
    externalAiIncluded: false,
    promptExecutionOperationAvailable: false,
    executionAuthorized: false,
    interventionRequired: true,
    futureGateRequirements: Object.freeze([
      "Bind the exact accepted Batch 439-450 capability observation archive.",
      "Record the reviewed disclosure and an explicit affirmative user decision.",
      "Bind a fresh trusted single-use gesture to the microphone permission control.",
      "Run a separate controlled package that authorizes at most one browser prompt.",
      "Stop before device enumeration or capture and return the prompt outcome as evidence.",
    ]),
  });
}
