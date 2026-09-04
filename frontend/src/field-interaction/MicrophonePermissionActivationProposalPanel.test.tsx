import { render, screen } from "@testing-library/react";
import { MicrophonePermissionActivationProposalPanel } from "./MicrophonePermissionActivationProposalPanel";

describe("microphone permission activation proposal presentation", () => {
  it("presents reviewed evidence and disclosure without a prompt control", () => {
    render(<MicrophonePermissionActivationProposalPanel />);
    expect(screen.getByRole("heading", { name: "Microphone permission activation proposal" })).toBeInTheDocument();
    expect(screen.getByText("Capability evidence accepted")).toBeInTheDocument();
    expect(screen.getByText("Consent not recorded")).toBeInTheDocument();
    expect(screen.getByText("Trusted gesture not recorded")).toBeInTheDocument();
    expect(screen.getByText("Prompt execution gate closed")).toBeInTheDocument();
    expect(screen.getByText("Microphone only")).toBeInTheDocument();
    expect(screen.getByText("Accepted Batch 439-450")).toBeInTheDocument();
    expect(screen.getByText("consent_required")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
