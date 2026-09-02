import { BACKEND_OPERATIONS } from "../api/operation-registry";
import type { AuthenticationProviderPort } from "./adapter";
import { createBackendAuthorizationProfile } from "./authorization";
import { createAuthenticationBearerTokenProvider } from "./api-token-provider";
import { normalizeIdentityAccount } from "./identity";
import {
  applyBackendAuthorizationProfile,
  beginAuthenticationInitialization,
  createInitialAuthenticationSnapshot,
  establishAuthenticatedIdentity,
} from "./session";

const READINESS = {
  ready: true,
  missing: [],
  issues: [],
  clientId: "11111111-2222-3333-4444-555555555555",
  authority: "https://example.test/",
  apiScope: "api://example.test/access",
} as const;

describe("authentication bearer-token provider bridge", () => {
  it("returns null without invoking the provider while the session is inactive", async () => {
    const requestAccessToken = vi.fn(async () => "synthetic-token");
    const provider: AuthenticationProviderPort = {
      initialize: async () => ({ state: "inactive" }),
      requestInteractiveSession: async () => ({ subjectId: "subject-1", tenantId: "tenant-1" }),
      requestAccessToken,
      endSession: async () => undefined,
    };
    const bridge = createAuthenticationBearerTokenProvider({
      provider,
      getSnapshot: () => createInitialAuthenticationSnapshot(READINESS),
      apiScope: READINESS.apiScope,
    });
    await expect(bridge.getAccessToken({ operation: BACKEND_OPERATIONS[2]!, correlationId: "correlation-1" }))
      .resolves.toBeNull();
    expect(requestAccessToken).not.toHaveBeenCalled();
  });

  it("delegates only from an authenticated backend-authorized snapshot without caching", async () => {
    const principal = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });
    const identified = establishAuthenticatedIdentity(
      beginAuthenticationInitialization(createInitialAuthenticationSnapshot(READINESS)),
      principal,
    );
    const authorized = applyBackendAuthorizationProfile(identified, createBackendAuthorizationProfile({
      authority: "backend",
      principalKey: principal.principalKey,
      revision: "profile-1",
    }, principal));
    const requestAccessToken = vi.fn(async () => "synthetic-token");
    const provider: AuthenticationProviderPort = {
      initialize: async () => ({ state: "inactive" }),
      requestInteractiveSession: async () => ({ subjectId: "subject-1", tenantId: "tenant-1" }),
      requestAccessToken,
      endSession: async () => undefined,
    };
    const bridge = createAuthenticationBearerTokenProvider({ provider, getSnapshot: () => authorized, apiScope: READINESS.apiScope });
    await expect(bridge.getAccessToken({ operation: BACKEND_OPERATIONS[2]!, correlationId: "correlation-2" }))
      .resolves.toBe("synthetic-token");
    expect(requestAccessToken).toHaveBeenCalledTimes(1);
  });
});
