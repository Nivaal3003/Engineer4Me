export const PAGE_LIMIT_DEFAULT = 25 as const;
export const PAGE_LIMIT_MAXIMUM = 200 as const;

export interface PageRequest {
  readonly offset: number;
  readonly limit: number;
}

export interface PageEnvelope<T> {
  readonly items: readonly T[];
  readonly offset: number;
  readonly limit: number;
  readonly total: number | null;
  readonly nextOffset: number | null;
}

export class InvalidPageRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPageRequestError";
  }
}

function boundedInteger(label: string, value: unknown, minimum: number, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new InvalidPageRequestError(
      `${label} must be a safe integer from ${minimum} through ${maximum}.`,
    );
  }
  return value;
}

export function createPageRequest(input: {
  readonly offset?: number;
  readonly limit?: number;
} = {}): PageRequest {
  return Object.freeze({
    offset: boundedInteger("offset", input.offset ?? 0, 0, Number.MAX_SAFE_INTEGER),
    limit: boundedInteger(
      "limit",
      input.limit ?? PAGE_LIMIT_DEFAULT,
      1,
      PAGE_LIMIT_MAXIMUM,
    ),
  });
}

export function createPageEnvelope<T>(input: {
  readonly items: readonly T[];
  readonly request: PageRequest;
  readonly total?: number | null;
}): PageEnvelope<T> {
  const total = input.total ?? null;
  if (total !== null) {
    boundedInteger("total", total, 0, Number.MAX_SAFE_INTEGER);
  }
  const consumed = input.request.offset + input.items.length;
  const nextOffset =
    input.items.length < input.request.limit || (total !== null && consumed >= total)
      ? null
      : consumed;
  return Object.freeze({
    items: Object.freeze([...input.items]),
    offset: input.request.offset,
    limit: input.request.limit,
    total,
    nextOffset,
  });
}
