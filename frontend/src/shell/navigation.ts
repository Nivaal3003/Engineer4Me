import { CAPABILITY_AREAS, type CapabilityAreaDefinition } from "../foundation";

export type ShellNavigationState = "current" | "planned" | "controlled";

export interface ShellNavigationItem extends CapabilityAreaDefinition {
  readonly state: ShellNavigationState;
  readonly inPageTarget: string | null;
}

export const SHELL_NAVIGATION_ITEMS: readonly ShellNavigationItem[] = Object.freeze(
  CAPABILITY_AREAS.map((area): ShellNavigationItem => ({
    ...area,
    state:
      area.id === "home"
        ? "current"
        : area.availability === "controlled_administration"
          ? "controlled"
          : "planned",
    inPageTarget: area.id === "home" ? "#main-content" : null,
  })),
);

export function currentNavigationItems(): readonly ShellNavigationItem[] {
  return SHELL_NAVIGATION_ITEMS.filter((item) => item.state === "current");
}
