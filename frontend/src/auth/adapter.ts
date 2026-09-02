import type { IdentityAccountInput } from "./identity";

export interface AuthenticationTokenRequest {
  readonly apiScope: string;
  readonly correlationId: string;
  readonly operationKey: string;
  readonly principalKey: string;
}

export type AuthenticationProviderInitialization =
  | { readonly state: "inactive" }
  | { readonly state: "account_available"; readonly account: IdentityAccountInput };

export interface AuthenticationProviderPort {
  initialize(): Promise<AuthenticationProviderInitialization>;
  requestInteractiveSession(correlationId: string): Promise<IdentityAccountInput>;
  requestAccessToken(request: AuthenticationTokenRequest): Promise<string | null>;
  endSession(correlationId: string): Promise<void>;
}

export class AuthenticationActivationRequiredError extends Error {
  readonly code = "authentication_activation_required";

  constructor() {
    super("Authentication provider execution is not active in this controlled build.");
    this.name = "AuthenticationActivationRequiredError";
  }
}

export const INACTIVE_AUTHENTICATION_PROVIDER: AuthenticationProviderPort = Object.freeze({
  initialize: async (): Promise<AuthenticationProviderInitialization> => ({ state: "inactive" }),
  requestInteractiveSession: async () => {
    throw new AuthenticationActivationRequiredError();
  },
  requestAccessToken: async () => null,
  endSession: async () => undefined,
});
