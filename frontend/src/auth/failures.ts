const CORRELATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export type AuthenticationFailureKind =
  | "activation_blocked"
  | "cancelled"
  | "interaction_required"
  | "identity_unavailable"
  | "token_unavailable"
  | "profile_unavailable"
  | "provider_error";

export interface AuthenticationFailure {
  readonly kind: AuthenticationFailureKind;
  readonly safeMessage: string;
  readonly correlationId: string;
  readonly retryAutomatically: false;
}

function controlledCorrelationId(value: string): string {
  if (!CORRELATION_ID.test(value)) {
    throw new Error("Authentication correlation identifier is invalid.");
  }
  return value;
}

export function normalizeAuthenticationFailure(
  error: unknown,
  correlationId: string,
): AuthenticationFailure {
  const id = controlledCorrelationId(correlationId);
  const record = typeof error === "object" && error !== null ? error as Record<string, unknown> : {};
  const code = typeof record.errorCode === "string" ? record.errorCode.toLowerCase() : "";
  const name = typeof record.name === "string" ? record.name : "";
  let kind: AuthenticationFailureKind = "provider_error";
  if (name === "AbortError" || code.includes("cancel")) kind = "cancelled";
  else if (code.includes("interaction_required") || name === "InteractionRequiredAuthError") kind = "interaction_required";
  else if (code.includes("no_account") || code.includes("identity")) kind = "identity_unavailable";
  else if (code.includes("token")) kind = "token_unavailable";
  else if (code.includes("profile")) kind = "profile_unavailable";
  else if (code.includes("activation")) kind = "activation_blocked";
  const messages: Record<AuthenticationFailureKind, string> = {
    activation_blocked: "Authentication activation requirements are not satisfied.",
    cancelled: "The authentication operation was cancelled.",
    interaction_required: "An explicit interactive authentication action is required.",
    identity_unavailable: "A controlled identity account is not available.",
    token_unavailable: "A controlled access token is not available.",
    profile_unavailable: "The backend authorization profile is not available.",
    provider_error: "The identity provider operation could not be completed.",
  };
  return Object.freeze({ kind, safeMessage: messages[kind], correlationId: id, retryAutomatically: false });
}
