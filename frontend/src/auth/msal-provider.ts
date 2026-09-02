import { bearerAuthorizationHeader } from "../api/token";
import type { AuthenticationActivationReadiness } from "./activation-readiness";
import type { AuthenticationRedirectPolicy } from "./redirect-policy";
import { resolveAuthenticationReturnPath } from "./redirect-policy";
import { normalizeIdentityAccount, type IdentityPrincipal } from "./identity";

export interface MsalAccountLike {
  readonly homeAccountId: string;
  readonly localAccountId: string;
  readonly tenantId: string;
  readonly username: string;
  readonly name?: string;
  readonly idTokenClaims?: Readonly<Record<string, unknown>>;
}

export interface MsalAuthenticationResultLike {
  readonly account: MsalAccountLike | null;
  readonly accessToken: string;
  readonly scopes: readonly string[];
  readonly expiresOn?: Date | null;
}

export interface MsalClientPort {
  initialize(): Promise<void>;
  handleRedirectPromise(options?: { readonly navigateToLoginRequestUrl?: boolean }): Promise<MsalAuthenticationResultLike | null>;
  loginRedirect(request: {
    readonly scopes: readonly string[];
    readonly correlationId: string;
    readonly redirectStartPage: string;
  }): Promise<void>;
  acquireTokenSilent(request: {
    readonly scopes: readonly string[];
    readonly correlationId: string;
    readonly account: MsalAccountLike;
  }): Promise<MsalAuthenticationResultLike>;
  logoutRedirect(request: {
    readonly account: MsalAccountLike;
    readonly correlationId: string;
    readonly postLogoutRedirectUri: string;
  }): Promise<void>;
  getAllAccounts(): readonly MsalAccountLike[];
  getActiveAccount(): MsalAccountLike | null;
  setActiveAccount(account: MsalAccountLike | null): void;
}

export type MsalInitializationResult =
  | { readonly state: "no_account" }
  | { readonly state: "account_available"; readonly principal: IdentityPrincipal }
  | { readonly state: "account_selection_required"; readonly accountCount: number };

export interface PreparedMsalAuthenticationProvider {
  initializeExplicitly(): Promise<MsalInitializationResult>;
  handleRedirectReturnExplicitly(): Promise<MsalInitializationResult>;
  beginInteractiveSignIn(correlationId: string, returnPath: string): Promise<{ readonly state: "redirect_started" }>;
  acquireAccessToken(correlationId: string, principal: IdentityPrincipal): Promise<string>;
  beginInteractiveSignOut(correlationId: string, principal: IdentityPrincipal): Promise<{ readonly state: "redirect_started" }>;
}

function requireActivation(readiness: AuthenticationActivationReadiness): void {
  if (!readiness.interactiveExecutionReady) {
    throw Object.assign(new Error("Authentication activation evidence is incomplete."), {
      errorCode: "activation_blocked",
    });
  }
}

function principalFromAccount(account: MsalAccountLike): IdentityPrincipal {
  const claims = account.idTokenClaims ?? {};
  const subjectId = typeof claims.oid === "string"
    ? claims.oid
    : typeof claims.sub === "string"
      ? claims.sub
      : account.localAccountId;
  const tenantId = typeof claims.tid === "string" ? claims.tid : account.tenantId;
  return normalizeIdentityAccount({
    subjectId,
    tenantId,
    username: account.username,
    displayName: account.name,
  });
}

function selectAccount(client: MsalClientPort): MsalAccountLike | null | "ambiguous" {
  const active = client.getActiveAccount();
  if (active) return active;
  const accounts = client.getAllAccounts();
  if (accounts.length === 0) return null;
  if (accounts.length > 1) return "ambiguous";
  const account = accounts[0] ?? null;
  client.setActiveAccount(account);
  return account;
}

function initializationResult(client: MsalClientPort): MsalInitializationResult {
  const account = selectAccount(client);
  if (account === "ambiguous") {
    return Object.freeze({ state: "account_selection_required", accountCount: client.getAllAccounts().length });
  }
  if (account === null) return Object.freeze({ state: "no_account" });
  return Object.freeze({ state: "account_available", principal: principalFromAccount(account) });
}

export function createPreparedMsalAuthenticationProvider(input: {
  readonly client: MsalClientPort;
  readonly readiness: AuthenticationActivationReadiness;
  readonly redirectPolicy: AuthenticationRedirectPolicy;
  readonly apiScope: string;
  readonly now?: () => number;
}): PreparedMsalAuthenticationProvider {
  const now = input.now ?? Date.now;
  return Object.freeze({
    initializeExplicitly: async () => {
      requireActivation(input.readiness);
      await input.client.initialize();
      return initializationResult(input.client);
    },
    handleRedirectReturnExplicitly: async () => {
      requireActivation(input.readiness);
      const result = await input.client.handleRedirectPromise({ navigateToLoginRequestUrl: false });
      if (result?.account) input.client.setActiveAccount(result.account);
      return initializationResult(input.client);
    },
    beginInteractiveSignIn: async (correlationId: string, returnPath: string) => {
      requireActivation(input.readiness);
      await input.client.loginRedirect({
        scopes: [input.apiScope],
        correlationId,
        redirectStartPage: resolveAuthenticationReturnPath(input.redirectPolicy, returnPath),
      });
      return Object.freeze({ state: "redirect_started" as const });
    },
    acquireAccessToken: async (correlationId: string, principal: IdentityPrincipal) => {
      requireActivation(input.readiness);
      const account = selectAccount(input.client);
      if (account === null || account === "ambiguous") {
        throw Object.assign(new Error("A unique active account is required."), { errorCode: "no_account" });
      }
      if (principalFromAccount(account).principalKey !== principal.principalKey) {
        throw Object.assign(new Error("The active account does not own this session."), { errorCode: "identity_mismatch" });
      }
      const result = await input.client.acquireTokenSilent({
        scopes: [input.apiScope],
        correlationId,
        account,
      });
      if (!result.scopes.includes(input.apiScope)) {
        throw Object.assign(new Error("The returned token scope differs."), { errorCode: "token_scope_mismatch" });
      }
      if (result.expiresOn && result.expiresOn.getTime() <= now() + 30_000) {
        throw Object.assign(new Error("The returned token is too close to expiry."), { errorCode: "token_expired" });
      }
      bearerAuthorizationHeader(result.accessToken);
      return result.accessToken;
    },
    beginInteractiveSignOut: async (correlationId: string, principal: IdentityPrincipal) => {
      requireActivation(input.readiness);
      const account = selectAccount(input.client);
      if (account === null || account === "ambiguous" || principalFromAccount(account).principalKey !== principal.principalKey) {
        throw Object.assign(new Error("The active account does not own this session."), { errorCode: "identity_mismatch" });
      }
      await input.client.logoutRedirect({
        account,
        correlationId,
        postLogoutRedirectUri: input.redirectPolicy.postLogoutRedirectUri,
      });
      return Object.freeze({ state: "redirect_started" as const });
    },
  });
}
