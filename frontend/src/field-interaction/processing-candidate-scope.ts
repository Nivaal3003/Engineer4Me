/** Declared candidate metadata only. No provider selection, file read or activation. */
export type ProcessingCandidateMode = "local_only_candidate" | "external_service_candidate";
export interface ProcessingCandidateScope {
  readonly dossierId: string;
  readonly revision: number;
  readonly mode: ProcessingCandidateMode;
  readonly processingRef: string;
  readonly processingRevision: string;
  readonly processingRevisionSha256: string;
  readonly deploymentRef: string;
  readonly dataLocationRef: string;
  readonly retentionPolicySha256: string;
  readonly languageTag: string;
  readonly purpose: "transcription_evaluation_only";
  readonly declarationOnly: true;
  readonly artifactBytesVerified: false;
  readonly providerSelectedByApplication: false;
  readonly executionAuthorized: false;
}
const issuedScopes = new WeakSet<object>();
const inputFields = ["dossierId", "revision", "mode", "processingRef", "processingRevision", "processingRevisionSha256", "deploymentRef", "dataLocationRef", "retentionPolicySha256", "languageTag", "purpose"] as const;
/** Reject accessors and extra own fields; copy values, without coercing or normalizing. */
export function processingEvidenceDataRecord(input: unknown, fields: readonly string[]): Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new Error("Processing evidence requires a plain data record.");
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("Processing evidence prototype differs.");
  const keys = Reflect.ownKeys(input);
  if (keys.length !== fields.length || keys.some(key => typeof key !== "string" || !fields.includes(key))) throw new Error("Processing evidence field inventory differs.");
  const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new Error("Processing evidence requires own enumerable data fields.");
    copy[field] = descriptor.value;
  }
  return copy;
}
export function processingEvidenceIdentifier(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(value)) throw new Error("Processing evidence identifier differs.");
  return value;
}
export function processingEvidenceDigest(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error("Processing evidence declared digest differs.");
  return value;
}
export function processingEvidenceInteger(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error("Processing evidence integer bound differs.");
  return value;
}
export function createProcessingCandidateScope(input: unknown): ProcessingCandidateScope {
  const value = processingEvidenceDataRecord(input, inputFields);
  if (value.mode !== "local_only_candidate" && value.mode !== "external_service_candidate") throw new Error("Processing candidate mode differs.");
  if (value.purpose !== "transcription_evaluation_only") throw new Error("Processing candidate purpose differs.");
  if (typeof value.languageTag !== "string" || !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(value.languageTag) || value.languageTag.length > 64) throw new Error("Processing candidate language declaration differs.");
  const result: ProcessingCandidateScope = Object.freeze({
    dossierId: processingEvidenceIdentifier(value.dossierId), revision: processingEvidenceInteger(value.revision, 1, 1000000),
    mode: value.mode, processingRef: processingEvidenceIdentifier(value.processingRef),
    processingRevision: processingEvidenceIdentifier(value.processingRevision), processingRevisionSha256: processingEvidenceDigest(value.processingRevisionSha256),
    deploymentRef: processingEvidenceIdentifier(value.deploymentRef), dataLocationRef: processingEvidenceIdentifier(value.dataLocationRef),
    retentionPolicySha256: processingEvidenceDigest(value.retentionPolicySha256), languageTag: value.languageTag, purpose: value.purpose,
    declarationOnly: true, artifactBytesVerified: false, providerSelectedByApplication: false, executionAuthorized: false,
  });
  issuedScopes.add(result);
  return result;
}
export function assertIssuedProcessingCandidateScope(scope: ProcessingCandidateScope): void {
  if (!issuedScopes.has(scope)) throw new Error("Processing candidate scope was not issued in this memory-only session.");
}
