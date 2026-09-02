import type { AuthenticationActivationReadiness } from "./activation-readiness";
import type { AuthenticationFailure } from "./failures";

export type AuthenticationActivationRuntimePhase =
  | "activation_blocked"
  | "ready_inactive"
  | "explicit_command_pending"
  | "redirect_pending"
  | "identity_pending_profile"
  | "authorized"
  | "error";

export interface AuthenticationActivationRuntimeSnapshot {
  readonly phase: AuthenticationActivationRuntimePhase;
  readonly automaticExecution: false;
  readonly browserPersistence: false;
  readonly lastCommand: string | null;
  readonly failure: AuthenticationFailure | null;
}

function freeze(value: AuthenticationActivationRuntimeSnapshot): AuthenticationActivationRuntimeSnapshot {
  return Object.freeze(value);
}

export function createAuthenticationActivationRuntimeSnapshot(
  readiness: AuthenticationActivationReadiness,
): AuthenticationActivationRuntimeSnapshot {
  return freeze({
    phase: readiness.interactiveExecutionReady ? "ready_inactive" : "activation_blocked",
    automaticExecution: false,
    browserPersistence: false,
    lastCommand: null,
    failure: null,
  });
}

export function beginExplicitAuthenticationCommand(
  current: AuthenticationActivationRuntimeSnapshot,
  command: string,
): AuthenticationActivationRuntimeSnapshot {
  const controlled = command.trim();
  if (current.phase !== "ready_inactive" || !/^[a-z][a-z0-9_]{0,63}$/u.test(controlled)) {
    throw new Error("Authentication runtime command is not permitted from the current state.");
  }
  return freeze({ ...current, phase: "explicit_command_pending", lastCommand: controlled, failure: null });
}

export function markAuthenticationRedirectPending(
  current: AuthenticationActivationRuntimeSnapshot,
): AuthenticationActivationRuntimeSnapshot {
  if (current.phase !== "explicit_command_pending") throw new Error("Redirect state requires an explicit pending command.");
  return freeze({ ...current, phase: "redirect_pending" });
}

export function markAuthenticationIdentityPendingProfile(
  current: AuthenticationActivationRuntimeSnapshot,
): AuthenticationActivationRuntimeSnapshot {
  if (!new Set<AuthenticationActivationRuntimePhase>(["explicit_command_pending", "redirect_pending"]).has(current.phase)) {
    throw new Error("Identity state requires an explicit authentication command.");
  }
  return freeze({ ...current, phase: "identity_pending_profile" });
}

export function markAuthenticationRuntimeFailure(
  current: AuthenticationActivationRuntimeSnapshot,
  failure: AuthenticationFailure,
): AuthenticationActivationRuntimeSnapshot {
  return freeze({ ...current, phase: "error", failure });
}
