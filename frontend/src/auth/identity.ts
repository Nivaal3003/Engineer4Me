import { normalizeBoundedText, normalizeOpaqueIdentifier } from "./values";

export interface IdentityAccountInput {
  readonly subjectId: unknown;
  readonly tenantId: unknown;
  readonly username?: unknown;
  readonly displayName?: unknown;
}

export interface IdentityPrincipal {
  readonly subjectId: string;
  readonly tenantId: string;
  readonly principalKey: string;
  readonly username: string | null;
  readonly displayName: string | null;
}

export function normalizeIdentityAccount(input: IdentityAccountInput): IdentityPrincipal {
  const subjectId = normalizeOpaqueIdentifier(input.subjectId, "Identity subject");
  const tenantId = normalizeOpaqueIdentifier(input.tenantId, "Identity tenant");
  return Object.freeze({
    subjectId,
    tenantId,
    principalKey: `${tenantId.length}:${tenantId}:${subjectId.length}:${subjectId}`,
    username: normalizeBoundedText(input.username, "Identity username", 254),
    displayName: normalizeBoundedText(input.displayName, "Identity display name", 160),
  });
}
