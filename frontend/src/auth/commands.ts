import type { AuthenticationActivationReadiness } from "./activation-readiness";

export type AuthenticationCommand =
  | "initialize"
  | "handle_redirect_return"
  | "begin_sign_in"
  | "acquire_access_token"
  | "begin_sign_out";

export interface AuthenticationCommandContext {
  readonly userInitiated: boolean;
  readonly redirectReturnPresent: boolean;
  readonly authenticatedIdentityPresent: boolean;
  readonly backendAuthorizationPresent: boolean;
}

export interface AuthenticationCommandDecision {
  readonly command: AuthenticationCommand;
  readonly allowed: boolean;
  readonly reason: string;
}

export function evaluateAuthenticationCommand(
  readiness: AuthenticationActivationReadiness,
  command: AuthenticationCommand,
  context: AuthenticationCommandContext,
): AuthenticationCommandDecision {
  if (!readiness.interactiveExecutionReady) {
    return Object.freeze({ command, allowed: false, reason: "Authentication activation evidence is incomplete." });
  }
  if (command === "handle_redirect_return") {
    return Object.freeze({
      command,
      allowed: context.redirectReturnPresent,
      reason: context.redirectReturnPresent
        ? "A reviewed redirect return is present."
        : "No reviewed redirect return is present.",
    });
  }
  if (command === "initialize") {
    return Object.freeze({ command, allowed: context.userInitiated, reason: context.userInitiated ? "Explicit initialization was requested." : "Automatic initialization is not authorized." });
  }
  if (command === "begin_sign_in") {
    return Object.freeze({ command, allowed: context.userInitiated, reason: context.userInitiated ? "Explicit sign-in was requested." : "Automatic sign-in is not authorized." });
  }
  if (command === "acquire_access_token") {
    const allowed = context.authenticatedIdentityPresent && context.backendAuthorizationPresent;
    return Object.freeze({ command, allowed, reason: allowed ? "Identity and backend authorization are established." : "Token acquisition requires identity and backend authorization." });
  }
  const allowed = context.userInitiated && context.authenticatedIdentityPresent;
  return Object.freeze({ command, allowed, reason: allowed ? "Explicit sign-out was requested for an established identity." : "Sign-out requires an explicit action and established identity." });
}
