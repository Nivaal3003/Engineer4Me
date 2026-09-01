import {
  CAPABILITY_AREAS,
  type CapabilityAreaDefinition,
  type CapabilityAreaId,
} from "../foundation";

export type RouteAccessRequirement =
  | "public"
  | "authenticated"
  | "entitled"
  | "controlled_administration";

export interface AppRouteDefinition {
  readonly id: CapabilityAreaId;
  readonly path: string;
  readonly label: string;
  readonly owner: string;
  readonly accessRequirement: RouteAccessRequirement;
  readonly requiredEntitlement: string | null;
  readonly capabilityAvailability: CapabilityAreaDefinition["availability"];
  readonly apiTransportRequired: boolean;
}

const ROUTE_SPECIFICATION: Readonly<
  Record<
    CapabilityAreaId,
    Pick<
      AppRouteDefinition,
      "path" | "accessRequirement" | "requiredEntitlement" | "apiTransportRequired"
    >
  >
> = Object.freeze({
  home: {
    path: "/",
    accessRequirement: "public",
    requiredEntitlement: null,
    apiTransportRequired: false,
  },
  selection: {
    path: "/selection",
    accessRequirement: "authenticated",
    requiredEntitlement: null,
    apiTransportRequired: true,
  },
  troubleshooting: {
    path: "/troubleshooting",
    accessRequirement: "authenticated",
    requiredEntitlement: null,
    apiTransportRequired: true,
  },
  knowledge: {
    path: "/knowledge",
    accessRequirement: "authenticated",
    requiredEntitlement: null,
    apiTransportRequired: true,
  },
  ingestion: {
    path: "/documents",
    accessRequirement: "authenticated",
    requiredEntitlement: null,
    apiTransportRequired: true,
  },
  calculations: {
    path: "/calculations",
    accessRequirement: "authenticated",
    requiredEntitlement: null,
    apiTransportRequired: true,
  },
  designs: {
    path: "/design-cases",
    accessRequirement: "entitled",
    requiredEntitlement: "engineering.designs.read",
    apiTransportRequired: true,
  },
  projects: {
    path: "/projects",
    accessRequirement: "entitled",
    requiredEntitlement: "engineering.projects.read",
    apiTransportRequired: true,
  },
  security: {
    path: "/access-audit",
    accessRequirement: "controlled_administration",
    requiredEntitlement: "security.audit.read",
    apiTransportRequired: true,
  },
});

export const APP_ROUTES: readonly AppRouteDefinition[] = Object.freeze(
  CAPABILITY_AREAS.map((area): AppRouteDefinition => {
    const specification = ROUTE_SPECIFICATION[area.id];
    return Object.freeze({
      id: area.id,
      path: specification.path,
      label: area.label,
      owner: area.owner,
      accessRequirement: specification.accessRequirement,
      requiredEntitlement: specification.requiredEntitlement,
      capabilityAvailability: area.availability,
      apiTransportRequired: specification.apiTransportRequired,
    });
  }),
);

const ROUTES_BY_ID: ReadonlyMap<CapabilityAreaId, AppRouteDefinition> = new Map(
  APP_ROUTES.map((route) => [route.id, route] as const),
);
const ROUTES_BY_PATH: ReadonlyMap<string, AppRouteDefinition> = new Map(
  APP_ROUTES.map((route) => [route.path, route] as const),
);

export function normalizeAppPath(pathname: string): string {
  const withoutQueryOrHash = pathname.split(/[?#]/u, 1)[0] ?? "/";
  const withLeadingSlash = withoutQueryOrHash.startsWith("/")
    ? withoutQueryOrHash
    : `/${withoutQueryOrHash}`;
  const collapsed = withLeadingSlash.replace(/\/{2,}/gu, "/");
  if (collapsed.length > 1 && collapsed.endsWith("/")) {
    return collapsed.replace(/\/+$/u, "");
  }
  return collapsed || "/";
}

export function routeById(id: CapabilityAreaId): AppRouteDefinition {
  const route = ROUTES_BY_ID.get(id);
  if (!route) {
    throw new Error(`Unknown Engineer4Me route id: ${id}`);
  }
  return route;
}

export function routeByPath(pathname: string): AppRouteDefinition | null {
  return ROUTES_BY_PATH.get(normalizeAppPath(pathname)) ?? null;
}

export function routeDocumentTitle(pathname: string): string {
  const route = routeByPath(pathname);
  return route ? `${route.label} — Engineer4Me` : "Page not found — Engineer4Me";
}

export function isKnownAppPath(pathname: string): boolean {
  return routeByPath(pathname) !== null;
}
