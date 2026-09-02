import { render, screen } from "@testing-library/react";
import { AccessAuditPanel } from "./AccessAuditPanel";

describe("controlled authentication audit presentation", () => {
  it("shows an explicit no-remote-data boundary when no records are supplied", () => {
    render(<AccessAuditPanel records={[]} />);
    expect(screen.getByRole("heading", { name: "Controlled authentication audit evidence" })).toBeInTheDocument();
    expect(screen.getByText("No remote audit records loaded")).toBeInTheDocument();
    expect(screen.getByText(/No audit API, browser persistence, Graph request/)).toBeInTheDocument();
  });

  it("presents safe audit records without arbitrary details", () => {
    render(<AccessAuditPanel records={[{
      eventId: "event-1",
      occurredAt: "2026-09-01T12:00:00.000Z",
      category: "configuration",
      outcome: "blocked",
      summary: "Configuration was evaluated",
    }]} />);
    expect(screen.getByText("Configuration was evaluated")).toBeInTheDocument();
    expect(screen.getByText("blocked")).toBeInTheDocument();
  });
});
