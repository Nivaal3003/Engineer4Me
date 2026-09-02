export type AccessValueKind = "role" | "entitlement";

const ACCESS_VALUE_PATTERN = /^[a-z0-9][a-z0-9._:-]{0,127}$/u;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/u;

export function normalizeAccessValues(
  values: readonly unknown[],
  kind: AccessValueKind,
  maximumCount = 128,
): readonly string[] {
  if (values.length > maximumCount) {
    throw new Error(`Too many ${kind} values.`);
  }
  const normalized = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") {
      throw new Error(`${kind} values must be strings.`);
    }
    const candidate = value.trim().toLowerCase();
    if (!ACCESS_VALUE_PATTERN.test(candidate)) {
      throw new Error(`${kind} value does not satisfy the controlled format.`);
    }
    normalized.add(candidate);
  }
  return Object.freeze([...normalized].sort());
}

export function normalizeBoundedText(
  value: unknown,
  label: string,
  maximumLength: number,
): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const candidate = value.trim();
  if (
    candidate.length === 0 ||
    candidate.length > maximumLength ||
    CONTROL_PATTERN.test(candidate)
  ) {
    throw new Error(`${label} does not satisfy the controlled text format.`);
  }
  return candidate;
}

export function normalizeOpaqueIdentifier(value: unknown, label: string): string {
  const candidate = normalizeBoundedText(value, label, 128);
  if (!candidate || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/u.test(candidate)) {
    throw new Error(`${label} does not satisfy the controlled identifier format.`);
  }
  return candidate;
}
