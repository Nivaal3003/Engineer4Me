/** Static source-layer ownership for the Engineer4Me frontend. */
export const SOURCE_LAYERS = [
  "entrypoint",
  "application",
  "shell",
  "routing",
  "workspace",
  "capability_workspace",
  "capabilities",
  "state_experience",
  "product_ui",
  "design_system",
  "architecture",
  "foundation",
  "contracts",
  "api",
  "authentication",
  "test",
] as const;

export type SourceLayer = (typeof SOURCE_LAYERS)[number];

export const SOURCE_LAYER_DEPENDENCIES: Readonly<
  Record<SourceLayer, readonly SourceLayer[]>
> = Object.freeze({
  entrypoint: ["application", "routing", "foundation", "authentication"],
  application: [
    "shell",
    "routing",
    "workspace",
    "capability_workspace",
    "capabilities",
    "state_experience",
    "product_ui",
    "design_system",
    "architecture",
    "foundation",
    "contracts",
    "api",
    "authentication",
  ],
  shell: ["shell", "routing", "product_ui", "design_system", "foundation"],
  routing: ["routing", "foundation", "authentication"],
  workspace: [
    "workspace",
    "capability_workspace",
    "capabilities",
    "routing",
    "state_experience",
    "product_ui",
    "design_system",
    "foundation",
    "contracts",
    "api",
    "authentication",
  ],
  capability_workspace: [
    "capability_workspace",
    "capabilities",
    "product_ui",
    "design_system",
    "foundation",
    "contracts",
  ],
  capabilities: ["capabilities", "api", "contracts", "foundation"],
  state_experience: ["state_experience", "design_system", "foundation"],
  product_ui: ["product_ui", "design_system", "foundation"],
  design_system: ["design_system", "foundation"],
  architecture: ["architecture", "foundation", "contracts"],
  foundation: ["foundation"],
  contracts: ["contracts", "foundation"],
  api: ["api", "contracts", "foundation"],
  authentication: ["authentication", "api", "contracts", "foundation"],
  test: SOURCE_LAYERS,
});

function normalizeSourcePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

export function classifySourceModule(path: string): SourceLayer {
  const normalized = normalizeSourcePath(path);
  if (
    normalized.includes("/test/") ||
    normalized.includes("/__tests__/") ||
    /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(normalized)
  ) return "test";
  if (normalized.endsWith("/main.tsx") || normalized === "main.tsx") return "entrypoint";
  if (normalized.includes("/architecture/")) return "architecture";
  if (normalized.includes("/foundation/")) return "foundation";
  if (normalized.includes("/contracts/")) return "contracts";
  if (normalized.includes("/api/")) return "api";
  if (normalized.includes("/design-system/")) return "design_system";
  if (normalized.includes("/product-ui/")) return "product_ui";
  if (normalized.includes("/state-experience/")) return "state_experience";
  if (normalized.includes("/capability-workspace/")) return "capability_workspace";
  if (normalized.includes("/capabilities/")) return "capabilities";
  if (normalized.includes("/workspaces/")) return "workspace";
  if (normalized.includes("/routing/")) return "routing";
  if (normalized.includes("/shell/")) return "shell";
  if (normalized.includes("/auth/")) return "authentication";
  return "application";
}

export interface SourceDependencyEvaluation {
  readonly from: string;
  readonly to: string;
  readonly fromLayer: SourceLayer;
  readonly toLayer: SourceLayer;
  readonly allowed: boolean;
}

export function evaluateSourceDependency(fromPath: string, toPath: string): SourceDependencyEvaluation {
  const fromLayer = classifySourceModule(fromPath);
  const toLayer = classifySourceModule(toPath);
  return {
    from: normalizeSourcePath(fromPath),
    to: normalizeSourcePath(toPath),
    fromLayer,
    toLayer,
    allowed: SOURCE_LAYER_DEPENDENCIES[fromLayer].includes(toLayer),
  };
}

export function isSourceDependencyAllowed(fromPath: string, toPath: string): boolean {
  return evaluateSourceDependency(fromPath, toPath).allowed;
}
