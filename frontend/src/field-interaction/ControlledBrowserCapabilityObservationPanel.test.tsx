import { render, screen } from "@testing-library/react";
import { ControlledBrowserCapabilityObservationPanel } from "./ControlledBrowserCapabilityObservationPanel";

describe("controlled browser capability observation presentation", () => {
  it("presents read-only evidence without an observation or activation control", () => {
    render(<ControlledBrowserCapabilityObservationPanel />);
    expect(screen.getByRole("heading", { name: "Controlled browser capability observation" })).toBeInTheDocument();
    expect(screen.getByText("Read-only capability evidence")).toBeInTheDocument();
    expect(screen.getByText("Permission methods not invoked")).toBeInTheDocument();
    expect(screen.getByText("Activation gate closed")).toBeInTheDocument();
    expect(screen.getByText("acceptance_archive_only")).toBeInTheDocument();
    expect(screen.getByText("http://127.0.0.1:<ephemeral>/phase10-capability-readiness")).toBeInTheDocument();
    expect(screen.getByText("Property presence only")).toBeInTheDocument();
    expect(screen.getByText("Secure and top-level")).toBeInTheDocument();
    expect(screen.getByText("microphone=(), camera=()")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
