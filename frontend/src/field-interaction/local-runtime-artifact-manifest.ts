/** Bounded declarations of future local artifacts; does not open, hash, download or load files. */
export const LOCAL_ARTIFACT_ROLES = Object.freeze([
  "engine_source", "model_weights", "runtime_bundle", "build_recipe", "dependency_inventory", "license_notices",
] as const);
export type LocalArtifactRole = typeof LOCAL_ARTIFACT_ROLES[number];
export interface LocalArtifactDeclaration {
  readonly role: LocalArtifactRole;
  readonly artifactRef: string;
  readonly revision: string;
  readonly sha256: string;
  readonly bytes: number;
}
export interface LocalArtifactManifest {
  readonly manifestRef: string;
  readonly engineCommit: string;
  readonly modelRef: string;
  readonly platformRef: string;
  readonly artifacts: readonly LocalArtifactDeclaration[];
  readonly contentVerified: false;
  readonly executionAuthorized: false;
}
const issued = new WeakSet<object>();
export function assessmentRef(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/.test(value)) throw new Error(`${label} reference differs`);
  return value;
}
export function assessmentDigest(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value) || /^([0-9a-f])\1+$/.test(value)) throw new Error("Artifact digest differs");
  return value;
}
export function assessmentInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${label} bound differs`);
  return value;
}
export function createLocalArtifactManifest(input: {
  readonly manifestRef: string; readonly engineCommit: string; readonly modelRef: string;
  readonly platformRef: string; readonly artifacts: readonly LocalArtifactDeclaration[];
}): LocalArtifactManifest {
  const manifestRef = assessmentRef(input.manifestRef, "Manifest");
  if (typeof input.engineCommit !== "string" || !/^[0-9a-f]{40}$/.test(input.engineCommit) || /^([0-9a-f])\1+$/.test(input.engineCommit)) throw new Error("Engine commit differs");
  if (!Array.isArray(input.artifacts) || input.artifacts.length !== LOCAL_ARTIFACT_ROLES.length) throw new Error("Artifact role inventory differs");
  const roles = new Set<LocalArtifactRole>(); const refs = new Set<string>();
  const artifacts = input.artifacts.map((artifact) => {
    if (!artifact || !LOCAL_ARTIFACT_ROLES.includes(artifact.role) || roles.has(artifact.role)) throw new Error("Artifact role inventory differs");
    roles.add(artifact.role);
    const ref = assessmentRef(artifact.artifactRef, "Artifact");
    if (refs.has(ref)) throw new Error("Duplicate artifact reference"); refs.add(ref);
    const revision = assessmentRef(artifact.revision, "Revision");
    if (/^(latest|main|master|head)$/i.test(revision)) throw new Error("Moving artifact revision is not permitted");
    return Object.freeze({role: artifact.role, artifactRef: ref, revision,
      sha256: assessmentDigest(artifact.sha256), bytes: assessmentInteger(artifact.bytes, 1, 4_294_967_296, "Artifact bytes")});
  });
  const result: LocalArtifactManifest = Object.freeze({manifestRef, engineCommit: input.engineCommit,
    modelRef: assessmentRef(input.modelRef, "Model"), platformRef: assessmentRef(input.platformRef, "Platform"),
    artifacts: Object.freeze(artifacts), contentVerified: false, executionAuthorized: false});
  issued.add(result); return result;
}
export function requireIssuedLocalArtifactManifest(value: LocalArtifactManifest): void {
  if (!value || !issued.has(value)) throw new Error("Local manifest was not issued here");
}
