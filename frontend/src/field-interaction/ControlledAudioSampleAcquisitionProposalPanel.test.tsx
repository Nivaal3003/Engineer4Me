import { render, screen, within } from "@testing-library/react";
import { ControlledAudioSampleAcquisitionProposalPanel } from "./ControlledAudioSampleAcquisitionProposalPanel";

describe("controlled audio sample acquisition proposal panel", () => {
  it("presents the bounded local proposal without an activation control", () => {
    render(<ControlledAudioSampleAcquisitionProposalPanel />);
    expect(screen.getByRole("heading", {
      name: "Bounded audio sample and signal-presence proposal",
    })).toBeInTheDocument();
    const region = screen.getByRole("region", {
      name: "Bounded audio sample and signal-presence proposal",
    });
    expect(within(region).getByText("Source session accepted")).toBeInTheDocument();
    expect(within(region).getByText("Sample access gate closed")).toBeInTheDocument();
    expect(within(region).getByText("2048 samples")).toBeInTheDocument();
    expect(within(region).getByText("8192 bytes")).toBeInTheDocument();
    expect(within(region).getByText("Not recorded")).toBeInTheDocument();
    expect(within(region).queryByRole("button")).not.toBeInTheDocument();
  });
});
