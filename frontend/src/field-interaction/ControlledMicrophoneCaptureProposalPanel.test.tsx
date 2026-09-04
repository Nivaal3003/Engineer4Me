import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ControlledMicrophoneCaptureProposalPanel } from "./ControlledMicrophoneCaptureProposalPanel";

describe("controlled microphone capture proposal panel", () => {
  it("presents the bounded proposal without an activation control", () => {
    render(<ControlledMicrophoneCaptureProposalPanel />);

    expect(
      screen.getByRole("heading", {
        name: "Bounded microphone source-session proposal",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("Permission outcome imported")).toBeInTheDocument();
    expect(screen.getByText("Capture consent not recorded")).toBeInTheDocument();
    expect(screen.getByText("Three-second ceiling")).toBeInTheDocument();
    expect(screen.getByText("Execution gate closed")).toBeInTheDocument();

    const boundary = screen.getByLabelText(
      "Bounded microphone source-session boundary",
    );
    expect(within(boundary).getByText("granted_tracks_stopped")).toBeInTheDocument();
    expect(within(boundary).getByText("3 seconds")).toBeInTheDocument();
    expect(within(boundary).getAllByText("Prohibited")).toHaveLength(3);
    expect(within(boundary).getByText("Unavailable")).toBeInTheDocument();
    expect(
      within(boundary).getByText("capture_specific_consent_required"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
