export type AuthenticationAuditCategory =
  | "configuration"
  | "identity"
  | "authorization"
  | "organisation"
  | "route_access"
  | "token_request"
  | "session";

export type AuthenticationAuditOutcome = "success" | "blocked" | "denied" | "error";
export type AuthenticationAuditDetailValue = string | number | boolean | null;

export interface AuthenticationAuditEventInput {
  readonly eventId: string;
  readonly occurredAt: string;
  readonly category: AuthenticationAuditCategory;
  readonly outcome: AuthenticationAuditOutcome;
  readonly summary: string;
  readonly correlationId?: string | null;
  readonly actorReference?: string | null;
  readonly details?: Readonly<Record<string, AuthenticationAuditDetailValue>>;
}

export interface AuthenticationAuditEvent extends AuthenticationAuditEventInput {
  readonly correlationId: string | null;
  readonly actorReference: string | null;
  readonly details: Readonly<Record<string, AuthenticationAuditDetailValue>>;
}

const AUTHENTICATION_AUDIT_CATEGORIES = new Set<AuthenticationAuditCategory>([
  "configuration",
  "identity",
  "authorization",
  "organisation",
  "route_access",
  "token_request",
  "session",
]);
const AUTHENTICATION_AUDIT_OUTCOMES = new Set<AuthenticationAuditOutcome>([
  "success",
  "blocked",
  "denied",
  "error",
]);
const FORBIDDEN_DETAIL_NAME = /(access.?token|id.?token|refresh.?token|authorization|password|secret|credential|cookie)/iu;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SAFE_DETAIL_KEY = /^[a-z][a-z0-9_]{0,63}$/u;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/u;

function safeText(value: string, label: string, maximum: number): string {
  const result = value.trim();
  if (result.length === 0 || result.length > maximum || CONTROL_PATTERN.test(result)) {
    throw new Error(`${label} is not safe for authentication audit evidence.`);
  }
  return result;
}

export function createAuthenticationAuditEvent(
  input: AuthenticationAuditEventInput,
): AuthenticationAuditEvent {
  if (!SAFE_IDENTIFIER.test(input.eventId)) throw new Error("Authentication audit event identifier is invalid.");
  if (!AUTHENTICATION_AUDIT_CATEGORIES.has(input.category)) throw new Error("Authentication audit category is invalid.");
  if (!AUTHENTICATION_AUDIT_OUTCOMES.has(input.outcome)) throw new Error("Authentication audit outcome is invalid.");
  const parsedTimestamp = Date.parse(input.occurredAt);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(input.occurredAt) ||
    Number.isNaN(parsedTimestamp) ||
    new Date(parsedTimestamp).toISOString() !== input.occurredAt
  ) {
    throw new Error("Authentication audit timestamp is invalid.");
  }
  const details = input.details ?? {};
  const entries = Object.entries(details);
  if (entries.length > 24) throw new Error("Authentication audit detail count is unbounded.");
  const normalizedDetails: Record<string, AuthenticationAuditDetailValue> = {};
  for (const [key, value] of entries) {
    if (!SAFE_DETAIL_KEY.test(key) || FORBIDDEN_DETAIL_NAME.test(key)) {
      throw new Error("Authentication audit detail name is forbidden.");
    }
    if (typeof value === "string") {
      normalizedDetails[key] = safeText(value, "Authentication audit detail", 256);
    } else if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error("Authentication audit numeric detail is not finite.");
      normalizedDetails[key] = value;
    } else if (typeof value === "boolean" || value === null) {
      normalizedDetails[key] = value;
    } else {
      throw new Error("Authentication audit detail type is forbidden.");
    }
  }
  const correlationId = input.correlationId ?? null;
  const actorReference = input.actorReference ?? null;
  if (correlationId !== null && !SAFE_IDENTIFIER.test(correlationId)) throw new Error("Audit correlation identifier is invalid.");
  if (actorReference !== null && !SAFE_IDENTIFIER.test(actorReference)) throw new Error("Audit actor reference is invalid.");
  return Object.freeze({
    eventId: input.eventId,
    occurredAt: input.occurredAt,
    category: input.category,
    outcome: input.outcome,
    summary: safeText(input.summary, "Authentication audit summary", 240),
    correlationId,
    actorReference,
    details: Object.freeze(normalizedDetails),
  });
}

export class BoundedMemoryAuthenticationAuditSink {
  readonly #capacity: number;
  readonly #events: AuthenticationAuditEvent[] = [];

  constructor(capacity = 100) {
    if (!Number.isInteger(capacity) || capacity < 1 || capacity > 100) {
      throw new Error("Authentication audit memory capacity must be between 1 and 100.");
    }
    this.#capacity = capacity;
  }

  append(event: AuthenticationAuditEvent): void {
    const controlled = createAuthenticationAuditEvent(event);
    if (this.#events.some((existing) => existing.eventId === controlled.eventId)) {
      throw new Error("Authentication audit event identifier is duplicated.");
    }
    this.#events.push(controlled);
    while (this.#events.length > this.#capacity) this.#events.shift();
  }

  list(): readonly AuthenticationAuditEvent[] {
    return Object.freeze([...this.#events]);
  }

  clear(): void {
    this.#events.length = 0;
  }
}
