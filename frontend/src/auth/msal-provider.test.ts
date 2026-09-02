import { normalizeIdentityAccount } from "./identity";
import { createAuthenticationRedirectPolicy } from "./redirect-policy";
import { createPreparedMsalAuthenticationProvider, type MsalAccountLike, type MsalClientPort } from "./msal-provider";

const ACCOUNT: MsalAccountLike = {
  homeAccountId: "home-1",
  localAccountId: "subject-1",
  tenantId: "tenant-1",
  username: "engineer@example.test",
};
const READY = {
  sourceReady: true,
  interactiveExecutionReady: true,
  missingGates: [],
  safeSummary: "ready",
} as const;
const POLICY = createAuthenticationRedirectPolicy({
  applicationOrigin: "https://engineer4me.example/",
  allowedReturnPaths: ["/", "/selection"],
});

function fakeClient() {
  let active: MsalAccountLike | null = ACCOUNT;
  return {
    initialize: async () => undefined,
    handleRedirectPromise: vi.fn(async () => null),
    loginRedirect: vi.fn(async () => undefined),
    acquireTokenSilent: async () => ({
      account: ACCOUNT,
      accessToken: "synthetic-token",
      scopes: ["api://example.test/access"],
      expiresOn: new Date(Date.now() + 120_000),
    }),
    logoutRedirect: async () => undefined,
    getAllAccounts: () => [ACCOUNT],
    getActiveAccount: () => active,
    setActiveAccount: (account: MsalAccountLike | null) => { active = account; },
  };
}

describe("prepared MSAL authentication provider", () => {
  it("requires explicit activation evidence before any provider operation", async () => {
    const provider = createPreparedMsalAuthenticationProvider({
      client: fakeClient(),
      readiness: { ...READY, interactiveExecutionReady: false },
      redirectPolicy: POLICY,
      apiScope: "api://example.test/access",
    });
    await expect(provider.initializeExplicitly()).rejects.toMatchObject({ errorCode: "activation_blocked" });
  });

  it("handles redirect return only through an explicit command with the v5 option location", async () => {
    const client = fakeClient();
    const provider = createPreparedMsalAuthenticationProvider({
      client,
      readiness: READY,
      redirectPolicy: POLICY,
      apiScope: "api://example.test/access",
    });
    await expect(provider.handleRedirectReturnExplicitly()).resolves.toMatchObject({ state: "account_available" });
    expect(client.handleRedirectPromise).toHaveBeenCalledWith({ navigateToLoginRequestUrl: false });
  });

  it("starts sign-in only for a reviewed return path and acquires a bounded silent token", async () => {
    const client = fakeClient();
    const provider = createPreparedMsalAuthenticationProvider({
      client,
      readiness: READY,
      redirectPolicy: POLICY,
      apiScope: "api://example.test/access",
    });
    await expect(provider.beginInteractiveSignIn("correlation-1", "/selection"))
      .resolves.toEqual({ state: "redirect_started" });
    expect(client.loginRedirect).toHaveBeenCalledWith(expect.objectContaining({
      redirectStartPage: "https://engineer4me.example/selection",
    }));
    const principal = normalizeIdentityAccount({ subjectId: "subject-1", tenantId: "tenant-1" });
    await expect(provider.acquireAccessToken("correlation-2", principal)).resolves.toBe("synthetic-token");
  });
});
