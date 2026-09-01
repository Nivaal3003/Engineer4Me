export const CORRELATION_ID_HEADER = "X-Correlation-ID" as const;
export const CORRELATION_ID_MAX_LENGTH = 128 as const;
const CORRELATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;

export function validateCorrelationId(value: string): string {
  if (!CORRELATION_ID_PATTERN.test(value)) {
    throw new Error("Correlation ID does not satisfy the controlled format.");
  }
  return value;
}

export function createCorrelationId(
  randomBytes: (length: number) => Uint8Array,
): string {
  const bytes = randomBytes(16);
  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
    throw new Error("Correlation ID entropy provider must return exactly 16 bytes.");
  }
  const hexadecimal = [...bytes]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
  return validateCorrelationId(`e4m-${hexadecimal}`);
}
