/**
 * Static source-layer ownership for the Engineer4Me frontend.
 *
 * This contract is intentionally independent of browser routing, API transport,
 * authentication activation, service workers, native packaging, and voice.
 */
export const SOURCE_LAYERS = [
  "entrypoint",
  "application",
  "architecture",
  "foundation",
  "authentication",
  "test",
] as const;

export type SourceLayer = (typeof SOURCE_LAYERS)[number];

export const SOURCE_LAYER_DEPENDENCIES: Readonly<
  Record<SourceLayer, readonly SourceLayer[]>
> = Object.freeze({
  entrypoint: ["application", "foundation", "authentication"],
  application: ["architecture", "foundation", "authentication"],
  architecture: ["architecture", "foundation"],
  foundation: ["foundation"],
  authentication: ["foundation", "authentication"],
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
  ) {
    return "test";
  }

  if (normalized.endsWith("/main.tsx") || normalized === "main.tsx") {
    return "entrypoint";
  }

  if (normalized.includes("/architecture/")) {
    return "architecture";
  }

  if (normalized.includes("/foundation/")) {
    return "foundation";
  }

  if (normalized.includes("/auth/")) {
    return "authentication";
  }

  return "application";
}

export interface SourceDependencyEvaluation {
  readonly from: string;
  readonly to: string;
  readonly fromLayer: SourceLayer;
  readonly toLayer: SourceLayer;
  readonly allowed: boolean;
}

export function evaluateSourceDependency(
  fromPath: string,
  toPath: string,
): SourceDependencyEvaluation {
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

export function isSourceDependencyAllowed(
  fromPath: string,
  toPath: string,
): boolean {
  return evaluateSourceDependency(fromPath, toPath).allowed;
}
