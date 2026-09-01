export type StateExperienceKind =
  | "loading"
  | "empty"
  | "error"
  | "degraded"
  | "unavailable"
  | "not_found";

export interface StateExperienceModel {
  readonly kind: StateExperienceKind;
  readonly eyebrow: string;
  readonly title: string;
  readonly detail: string;
  readonly guidance: readonly string[];
  readonly correlationId: string | null;
  readonly retryAuthorized: boolean;
}

const DEFAULT_STATE_MODELS: Readonly<Record<StateExperienceKind, StateExperienceModel>> =
  Object.freeze({
    loading: {
      kind: "loading",
      eyebrow: "Loading",
      title: "Preparing the requested view",
      detail: "The current operation has not completed.",
      guidance: ["Do not assume results are available until loading completes."],
      correlationId: null,
      retryAuthorized: false,
    },
    empty: {
      kind: "empty",
      eyebrow: "No records",
      title: "Nothing is available for this view",
      detail: "The request completed without a displayable record.",
      guidance: ["Review the selected context and filters before creating new work."],
      correlationId: null,
      retryAuthorized: false,
    },
    error: {
      kind: "error",
      eyebrow: "Request failed",
      title: "The requested view could not be completed",
      detail: "A controlled error occurred.",
      guidance: ["Preserve the correlation identifier when escalating the failure."],
      correlationId: null,
      retryAuthorized: false,
    },
    degraded: {
      kind: "degraded",
      eyebrow: "Degraded",
      title: "Only a limited view is available",
      detail: "Some required evidence or service state is unavailable.",
      guidance: ["Treat displayed information as incomplete until full service is restored."],
      correlationId: null,
      retryAuthorized: false,
    },
    unavailable: {
      kind: "unavailable",
      eyebrow: "Unavailable",
      title: "This function is not available",
      detail: "A required product or access gate has not been satisfied.",
      guidance: ["No protected data or engineering result has been disclosed."],
      correlationId: null,
      retryAuthorized: false,
    },
    not_found: {
      kind: "not_found",
      eyebrow: "Not found",
      title: "The requested page does not exist",
      detail: "The address does not match a controlled Engineer4Me route.",
      guidance: ["Return to the workspace and use the product navigation."],
      correlationId: null,
      retryAuthorized: false,
    },
  });

export function createStateExperience(
  kind: StateExperienceKind,
  overrides: Partial<Omit<StateExperienceModel, "kind">> = {},
): StateExperienceModel {
  return Object.freeze({
    ...DEFAULT_STATE_MODELS[kind],
    ...overrides,
    kind,
    guidance: Object.freeze([
      ...(overrides.guidance ?? DEFAULT_STATE_MODELS[kind].guidance),
    ]),
  });
}
