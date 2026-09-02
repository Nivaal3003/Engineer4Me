import type { BearerTokenProvider } from "../api/token";
import type { AuthenticationProviderPort } from "./adapter";
import { isBackendAuthorizedSession, type AuthenticationSnapshot } from "./session";

export interface AuthenticationBearerTokenProviderOptions {
  readonly provider: AuthenticationProviderPort;
  readonly getSnapshot: () => AuthenticationSnapshot;
  readonly apiScope: string;
}

/**
 * Implements the approved API bearer-provider seam without caching or persistence.
 * The running application does not construct or attach this provider in Batch 329-344.
 */
export function createAuthenticationBearerTokenProvider(
  options: AuthenticationBearerTokenProviderOptions,
): BearerTokenProvider {
  const provider: BearerTokenProvider = {
    getAccessToken: async ({ operation, correlationId }) => {
      const current = options.getSnapshot();
      if (!isBackendAuthorizedSession(current)) return null;
      return options.provider.requestAccessToken({
        apiScope: options.apiScope,
        correlationId,
        operationKey: operation.key,
        principalKey: current.principal.principalKey,
      });
    },
  };
  return Object.freeze(provider);
}
