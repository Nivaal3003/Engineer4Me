/** Fail-closed field-interaction source and transcript contracts. */
export const FIELD_INTERACTION_SOURCE_KINDS = [
  "manual_text",
  "scripted_voice_transcript",
  "scripted_image_descriptor",
  "scripted_document_descriptor",
] as const;

export type FieldInteractionSourceKind =
  (typeof FIELD_INTERACTION_SOURCE_KINDS)[number];

export type FieldInteractionCaptureMode = "manual" | "scripted";

export interface FieldInteractionSourceDescriptor {
  readonly sourceId: string;
  readonly kind: FieldInteractionSourceKind;
  readonly label: string;
  readonly mediaType: string | null;
  readonly declaredByteLength: number | null;
  readonly declaredSha256: string | null;
  readonly captureMode: FieldInteractionCaptureMode;
  readonly rawContentAvailable: false;
  readonly protectedContentLoaded: false;
  readonly permissionRequested: false;
  readonly externalProcessingUsed: false;
}

export interface ControlledTranscript {
  readonly transcriptId: string;
  readonly sourceId: string;
  readonly sourceKind: "manual_text" | "scripted_voice_transcript";
  readonly languageTag: string;
  readonly text: string;
  readonly isFinal: true;
  readonly confidence: null;
  readonly rawAudioAvailable: false;
  readonly microphonePermissionRequested: false;
  readonly externalAiUsed: false;
  readonly protectedContentLoaded: false;
}

const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const MEDIA_TYPE_PATTERN =
  /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const LANGUAGE_TAG_PATTERN = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/;
const CONTROL_CHARACTER_PATTERN =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function boundedText(value: string, label: string, maximum: number): string {
  const normalized = value.trim().replace(/\s+/g, " ");
  if (normalized.length === 0) {
    throw new Error(`${label} is required.`);
  }
  if (normalized.length > maximum) {
    throw new Error(`${label} exceeds ${maximum} characters.`);
  }
  if (CONTROL_CHARACTER_PATTERN.test(normalized)) {
    throw new Error(`${label} contains a disallowed control character.`);
  }
  return normalized;
}

export function validateFieldInteractionIdentifier(
  value: string,
  label = "Field-interaction identifier",
): string {
  const normalized = value.trim();
  if (!IDENTIFIER_PATTERN.test(normalized)) {
    throw new Error(`${label} must use the controlled identifier format.`);
  }
  return normalized;
}

export function createFieldInteractionSourceDescriptor(input: {
  readonly sourceId: string;
  readonly kind: FieldInteractionSourceKind;
  readonly label: string;
  readonly mediaType?: string | null;
  readonly declaredByteLength?: number | null;
  readonly declaredSha256?: string | null;
  readonly captureMode: FieldInteractionCaptureMode;
}): FieldInteractionSourceDescriptor {
  const sourceId = validateFieldInteractionIdentifier(input.sourceId, "Source identifier");
  const label = boundedText(input.label, "Source label", 160);
  const mediaType = input.mediaType?.trim().toLowerCase() ?? null;
  if (mediaType !== null && !MEDIA_TYPE_PATTERN.test(mediaType)) {
    throw new Error("Media type is not a controlled MIME type.");
  }
  const declaredByteLength = input.declaredByteLength ?? null;
  if (
    declaredByteLength !== null &&
    (!Number.isSafeInteger(declaredByteLength) || declaredByteLength < 0)
  ) {
    throw new Error("Declared byte length must be a non-negative safe integer.");
  }
  const declaredSha256 = input.declaredSha256?.trim().toLowerCase() ?? null;
  if (declaredSha256 !== null && !SHA256_PATTERN.test(declaredSha256)) {
    throw new Error("Declared SHA-256 must be exactly 64 lowercase hexadecimal characters.");
  }
  return Object.freeze({
    sourceId,
    kind: input.kind,
    label,
    mediaType,
    declaredByteLength,
    declaredSha256,
    captureMode: input.captureMode,
    rawContentAvailable: false,
    protectedContentLoaded: false,
    permissionRequested: false,
    externalProcessingUsed: false,
  });
}

export function createControlledTranscript(input: {
  readonly transcriptId: string;
  readonly sourceId: string;
  readonly sourceKind: "manual_text" | "scripted_voice_transcript";
  readonly languageTag: string;
  readonly text: string;
}): ControlledTranscript {
  const languageTag = input.languageTag.trim();
  if (!LANGUAGE_TAG_PATTERN.test(languageTag)) {
    throw new Error("Transcript language tag is invalid.");
  }
  return Object.freeze({
    transcriptId: validateFieldInteractionIdentifier(
      input.transcriptId,
      "Transcript identifier",
    ),
    sourceId: validateFieldInteractionIdentifier(input.sourceId, "Source identifier"),
    sourceKind: input.sourceKind,
    languageTag,
    text: boundedText(input.text, "Transcript text", 4096),
    isFinal: true,
    confidence: null,
    rawAudioAvailable: false,
    microphonePermissionRequested: false,
    externalAiUsed: false,
    protectedContentLoaded: false,
  });
}
