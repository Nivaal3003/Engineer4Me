import { BoundedMemoryAuthenticationAuditSink, createAuthenticationAuditEvent } from "./audit";

function event(sequence: number) {
  return createAuthenticationAuditEvent({
    eventId: `event-${sequence}`,
    occurredAt: "2026-09-01T12:00:00.000Z",
    category: "session",
    outcome: "blocked",
    summary: `Controlled event ${sequence}`,
    details: { sequence },
  });
}

describe("redacted bounded authentication audit evidence", () => {
  it("retains only the bounded newest events in memory", () => {
    const sink = new BoundedMemoryAuthenticationAuditSink(2);
    sink.append(event(1));
    sink.append(event(2));
    sink.append(event(3));
    expect(sink.list().map((item) => item.eventId)).toEqual(["event-2", "event-3"]);
  });

  it("rejects token, authorization, credential, and secret detail names", () => {
    for (const key of ["access_token", "authorization", "password", "client_secret"]) {
      expect(() => createAuthenticationAuditEvent({
        eventId: "event-1",
        occurredAt: "2026-09-01T12:00:00.000Z",
        category: "token_request",
        outcome: "denied",
        summary: "Rejected detail",
        details: { [key]: "forbidden" },
      })).toThrow(/forbidden/u);
    }
  });

  it("drops unexpected input properties and rejects duplicate event identifiers", () => {
    const controlled = createAuthenticationAuditEvent({
      eventId: "event-1",
      occurredAt: "2026-09-01T12:00:00.000Z",
      category: "session",
      outcome: "success",
      summary: "Controlled event",
      accessToken: "must-not-survive",
    } as Parameters<typeof createAuthenticationAuditEvent>[0] & { accessToken: string });
    expect(controlled).not.toHaveProperty("accessToken");

    const sink = new BoundedMemoryAuthenticationAuditSink(2);
    sink.append(controlled);
    expect(() => sink.append(controlled)).toThrow(/duplicated/u);
  });

  it("rejects non-canonical timestamps and invalid runtime categories", () => {
    expect(() => createAuthenticationAuditEvent({
      eventId: "event-1",
      occurredAt: "2026-09-01",
      category: "session",
      outcome: "success",
      summary: "Controlled event",
    })).toThrow(/timestamp/u);
    expect(() => createAuthenticationAuditEvent({
      eventId: "event-2",
      occurredAt: "2026-09-01T12:00:00.000Z",
      category: "unexpected",
      outcome: "success",
      summary: "Controlled event",
    } as unknown as Parameters<typeof createAuthenticationAuditEvent>[0])).toThrow(/category/u);
  });
});
