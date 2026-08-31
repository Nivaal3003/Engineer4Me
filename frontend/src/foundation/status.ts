/** Shared fail-closed status contracts for later Engineer4Me UI components. */
export type AsyncViewState =
  | "idle"
  | "loading"
  | "ready"
  | "empty"
  | "error"
  | "degraded"
  | "unavailable";

export type ConnectivityState =
  | "unknown"
  | "online"
  | "offline"
  | "degraded";

export type AccessDecisionState =
  | "unknown"
  | "inactive"
  | "denied"
  | "allowed";

export interface ProductStatusViewModel {
  readonly view: AsyncViewState;
  readonly connectivity: ConnectivityState;
  readonly access: AccessDecisionState;
  readonly title: string;
  readonly detail?: string;
  readonly correlationId?: string;
  readonly retryAuthorized: boolean;
}

export const INITIAL_PRODUCT_STATUS: Readonly<ProductStatusViewModel> =
  Object.freeze({
    view: "idle",
    connectivity: "unknown",
    access: "inactive",
    title: "Engineer4Me is not yet connected",
    retryAuthorized: false,
  });
