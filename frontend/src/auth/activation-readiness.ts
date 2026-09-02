import type { AuthenticationConfigurationReadiness } from "./config";
import type { AuthenticationRedirectPolicy } from "./redirect-policy";

export const AUTHENTICATION_ACTIVATION_GATES = [
  "public_configuration_valid",
  "redirect_policy_reviewed",
  "application_registration_reviewed",
  "redirect_uri_registration_proven",
  "delegated_api_permission_consent_proven",
  "calling_client_association_proven",
  "external_id_user_flow_association_proven",
  "history_fallback_proven",
  "supported_deployment_environment_proven",
] as const;

export type AuthenticationActivationGate =
  (typeof AUTHENTICATION_ACTIVATION_GATES)[number];

export interface AuthenticationActivationEvidence {
  readonly applicationRegistrationReviewed: boolean;
  readonly redirectUriRegistrationProven: boolean;
  readonly delegatedApiPermissionConsentProven: boolean;
  readonly callingClientAssociationProven: boolean;
  readonly externalIdUserFlowAssociationProven: boolean;
  readonly historyFallbackProven: boolean;
  readonly supportedDeploymentEnvironmentProven: boolean;
}

export const NO_AUTHENTICATION_ACTIVATION_EVIDENCE: AuthenticationActivationEvidence =
  Object.freeze({
    applicationRegistrationReviewed: false,
    redirectUriRegistrationProven: false,
    delegatedApiPermissionConsentProven: false,
    callingClientAssociationProven: false,
    externalIdUserFlowAssociationProven: false,
    historyFallbackProven: false,
    supportedDeploymentEnvironmentProven: false,
  });

export interface AuthenticationActivationReadiness {
  readonly sourceReady: boolean;
  readonly interactiveExecutionReady: boolean;
  readonly missingGates: readonly AuthenticationActivationGate[];
  readonly safeSummary: string;
}

export function evaluateAuthenticationActivationReadiness(input: {
  readonly configuration: AuthenticationConfigurationReadiness;
  readonly redirectPolicy: AuthenticationRedirectPolicy | null;
  readonly evidence: AuthenticationActivationEvidence;
}): AuthenticationActivationReadiness {
  const gates: Readonly<Record<AuthenticationActivationGate, boolean>> = {
    public_configuration_valid: input.configuration.ready,
    redirect_policy_reviewed: input.redirectPolicy !== null,
    application_registration_reviewed: input.evidence.applicationRegistrationReviewed,
    redirect_uri_registration_proven: input.evidence.redirectUriRegistrationProven,
    delegated_api_permission_consent_proven: input.evidence.delegatedApiPermissionConsentProven,
    calling_client_association_proven: input.evidence.callingClientAssociationProven,
    external_id_user_flow_association_proven: input.evidence.externalIdUserFlowAssociationProven,
    history_fallback_proven: input.evidence.historyFallbackProven,
    supported_deployment_environment_proven: input.evidence.supportedDeploymentEnvironmentProven,
  };
  const missingGates = Object.freeze(
    AUTHENTICATION_ACTIVATION_GATES.filter((gate) => !gates[gate]),
  );
  const sourceReady = gates.public_configuration_valid && gates.redirect_policy_reviewed;
  const interactiveExecutionReady = missingGates.length === 0;
  return Object.freeze({
    sourceReady,
    interactiveExecutionReady,
    missingGates,
    safeSummary: interactiveExecutionReady
      ? "All reviewed activation evidence is present; execution still requires an explicit user action."
      : `${missingGates.length} reviewed activation gate${missingGates.length === 1 ? " is" : "s are"} not satisfied.`,
  });
}
