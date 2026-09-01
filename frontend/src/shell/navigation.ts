import { APP_ROUTES, type AppRouteDefinition } from "../routing";

export type ShellNavigationState =
  | "available"
  | "protected"
  | "entitled"
  | "controlled";

export interface ShellNavigationItem extends AppRouteDefinition {
  readonly state: ShellNavigationState;
  readonly stateLabel: string;
}

export const SHELL_NAVIGATION_ITEMS: readonly ShellNavigationItem[] = Object.freeze(
  APP_ROUTES.map((route): ShellNavigationItem => {
    const state: ShellNavigationState =
      route.accessRequirement === "public"
        ? "available"
        : route.accessRequirement === "authenticated"
          ? "protected"
          : route.accessRequirement === "entitled"
            ? "entitled"
            : "controlled";
    const stateLabel =
      state === "available"
        ? "Available"
        : state === "protected"
          ? "Protected"
          : state === "entitled"
            ? "Entitled"
            : "Controlled";
    return Object.freeze({ ...route, state, stateLabel });
  }),
);

export function navigationItemByPath(path: string): ShellNavigationItem | null {
  return SHELL_NAVIGATION_ITEMS.find((item) => item.path === path) ?? null;
}
