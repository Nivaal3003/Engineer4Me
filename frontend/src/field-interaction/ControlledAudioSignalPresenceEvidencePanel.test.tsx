import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ControlledAudioSignalPresenceEvidencePanel } from "./ControlledAudioSignalPresenceEvidencePanel";

describe("controlled audio signal-presence evidence panel", () => {
  it("presents the minimized evidence boundary without an activation control", () => {
    render(<ControlledAudioSignalPresenceEvidencePanel acceptedOutcome="signal_present" />);

    const evidenceRegion = screen.getByRole("region", {
      name: "Local microphone signal-presence boundary",
    });

    expect(evidenceRegion).toBeInTheDocument();
    expect(evidenceRegion).toHaveAttribute(
      "aria-labelledby",
      "controlled-signal-presence-heading",
    );
    expect(
      within(evidenceRegion).getByText("Local signal detected"),
    ).toBeInTheDocument();
    expect(within(evidenceRegion).queryByRole("button")).not.toBeInTheDocument();
  });
});
