import type { FieldInteractionPermissionKind } from "./permissions";

export const PERMISSIONS_POLICY_HEADER_NAME = "Permissions-Policy" as const;
export const DEFAULT_DENY_PERMISSIONS_POLICY_VALUE =
  "microphone=(), camera=()" as const;
export const FUTURE_CONTROLLED_SELF_PERMISSIONS_POLICY_VALUE =
  "microphone=(self), camera=(self)" as const;

export type DeploymentPermissionDirective = "deny" | "allow_self";
export type DeploymentPermissionsPolicyParseState =
  | "absent"
  | "accepted"
  | "invalid";

export interface DeploymentPermissionsPolicyParseResult {
  readonly state: DeploymentPermissionsPolicyParseState;
  readonly headerName: typeof PERMISSIONS_POLICY_HEADER_NAME;
  readonly suppliedValue: string | null;
  readonly canonicalValue: string | null;
  readonly microphoneDirective: DeploymentPermissionDirective | null;
  readonly cameraDirective: DeploymentPermissionDirective | null;
  readonly exactControlledDirectiveSet: boolean;
  readonly blockingReasons: readonly string[];
  readonly liveResponseHeaderRead: false;
  readonly networkRequestPerformed: false;
  readonly permissionsPolicyMethodCalled: false;
  readonly permissionStatusQueried: false;
  readonly permissionPromptShown: false;
}

const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const DIRECTIVE_PATTERN = /^(microphone|camera)\s*=\s*\(\s*(self)?\s*\)$/i;

function invalidResult(
  suppliedValue: string | null,
  reasons: readonly string[],
): DeploymentPermissionsPolicyParseResult {
  return Object.freeze({
    state: suppliedValue === null ? "absent" : "invalid",
    headerName: PERMISSIONS_POLICY_HEADER_NAME,
    suppliedValue,
    canonicalValue: null,
    microphoneDirective: null,
    cameraDirective: null,
    exactControlledDirectiveSet: false,
    blockingReasons: Object.freeze([...reasons]),
    liveResponseHeaderRead: false,
    networkRequestPerformed: false,
    permissionsPolicyMethodCalled: false,
    permissionStatusQueried: false,
    permissionPromptShown: false,
  });
}

export function parseDeploymentPermissionsPolicyValue(
  value: string | null | undefined,
): DeploymentPermissionsPolicyParseResult {
  if (value === null || value === undefined || value.trim().length === 0) {
    return invalidResult(null, [
      "Reviewed deployment Permissions-Policy header evidence is required.",
    ]);
  }
  const suppliedValue = value.trim();
  if (suppliedValue.length > 512) {
    return invalidResult(suppliedValue, [
      "The supplied Permissions-Policy value exceeds the controlled length boundary.",
    ]);
  }
  if (CONTROL_CHARACTER_PATTERN.test(suppliedValue)) {
    return invalidResult(suppliedValue, [
      "The supplied Permissions-Policy value contains a control character.",
    ]);
  }

  const observed = new Map<
    FieldInteractionPermissionKind,
    DeploymentPermissionDirective
  >();
  const reasons: string[] = [];
  for (const part of suppliedValue.split(",")) {
    const candidate = part.trim();
    const match = DIRECTIVE_PATTERN.exec(candidate);
    if (match === null) {
      reasons.push(
        `Unsupported or malformed Permissions-Policy directive: ${candidate || "<empty>"}.`,
      );
      continue;
    }
    const permission = match[1]!.toLowerCase() as FieldInteractionPermissionKind;
    if (observed.has(permission)) {
      reasons.push(`Duplicate ${permission} directive is not accepted.`);
      continue;
    }
    observed.set(permission, match[2] === undefined ? "deny" : "allow_self");
  }

  for (const permission of ["microphone", "camera"] as const) {
    if (!observed.has(permission)) {
      reasons.push(`Required ${permission} directive is absent.`);
    }
  }
  if (reasons.length > 0) {
    return invalidResult(suppliedValue, reasons);
  }

  const microphoneDirective = observed.get("microphone")!;
  const cameraDirective = observed.get("camera")!;
  const canonicalValue = [
    `microphone=${microphoneDirective === "allow_self" ? "(self)" : "()"}`,
    `camera=${cameraDirective === "allow_self" ? "(self)" : "()"}`,
  ].join(", ");
  return Object.freeze({
    state: "accepted",
    headerName: PERMISSIONS_POLICY_HEADER_NAME,
    suppliedValue,
    canonicalValue,
    microphoneDirective,
    cameraDirective,
    exactControlledDirectiveSet: true,
    blockingReasons: Object.freeze([]),
    liveResponseHeaderRead: false,
    networkRequestPerformed: false,
    permissionsPolicyMethodCalled: false,
    permissionStatusQueried: false,
    permissionPromptShown: false,
  });
}

export function deploymentDirectiveFor(
  permission: FieldInteractionPermissionKind,
  result: DeploymentPermissionsPolicyParseResult,
): DeploymentPermissionDirective | null {
  return permission === "microphone"
    ? result.microphoneDirective
    : result.cameraDirective;
}
