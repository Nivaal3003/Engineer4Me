import { render, screen } from "@testing-library/react";
import { ControlledBrowserNavigationEvidencePanel } from "./ControlledBrowserNavigationEvidencePanel";

describe("controlled browser navigation evidence presentation", () => {
  it("presents one verifier-only navigation without exposing an activation control", () => {
    render(<ControlledBrowserNavigationEvidencePanel />);
    expect(screen.getByRole("heading", { name: "Controlled headless browser navigation evidence" })).toBeInTheDocument();
    expect(screen.getByText("One loopback navigation controlled")).toBeInTheDocument();
    expect(screen.getByText("Application browser launch closed")).toBeInTheDocument();
    expect(screen.getByText("Permission prompts closed")).toBeInTheDocument();
    expect(screen.getByText("acceptance_archive_only")).toBeInTheDocument();
    expect(screen.getByText("http://127.0.0.1:<ephemeral>/phase10-readiness")).toBeInTheDocument();
    expect(screen.getByText("microphone=(), camera=()")).toBeInTheDocument();
    expect(screen.getByText("Not persisted")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
