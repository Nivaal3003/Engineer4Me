/** Branded, validated identifiers used at frontend/backend contract boundaries. */
declare const ENGINEER4ME_IDENTIFIER: unique symbol;

export type EngineeringIdentifier<TKind extends string> = string & {
  readonly [ENGINEER4ME_IDENTIFIER]: TKind;
};

export const IDENTIFIER_MAX_LENGTH = 128 as const;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

export class InvalidEngineeringIdentifierError extends Error {
  constructor(readonly kind: string, readonly suppliedValue: unknown) {
    super(`Invalid Engineer4Me ${kind} identifier.`);
    this.name = "InvalidEngineeringIdentifierError";
  }
}

export function parseEngineeringIdentifier<TKind extends string>(
  kind: TKind,
  value: unknown,
): EngineeringIdentifier<TKind> {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > IDENTIFIER_MAX_LENGTH ||
    !IDENTIFIER_PATTERN.test(value)
  ) {
    throw new InvalidEngineeringIdentifierError(kind, value);
  }
  return value as EngineeringIdentifier<TKind>;
}

export function engineeringIdentifierValue<TKind extends string>(
  identifier: EngineeringIdentifier<TKind>,
): string {
  return identifier;
}
