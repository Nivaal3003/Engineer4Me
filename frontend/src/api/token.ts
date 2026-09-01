import type { BackendOperationDefinition } from "./operation-registry";

export interface BearerTokenRequest {
  readonly operation: BackendOperationDefinition;
  readonly correlationId: string;
}

export interface BearerTokenProvider {
  getAccessToken(request: BearerTokenRequest): Promise<string | null>;
}

export const INACTIVE_BEARER_TOKEN_PROVIDER: BearerTokenProvider = Object.freeze({
  getAccessToken: async () => null,
});

export function bearerAuthorizationHeader(token: string): string {
  if (
    token.length === 0 ||
    token.length > 8192 ||
    /[\u0000-\u0020\u007f]/.test(token)
  ) {
    throw new Error("Bearer token does not satisfy the controlled header format.");
  }
  return `Bearer ${token}`;
}
