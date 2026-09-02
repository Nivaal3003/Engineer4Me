import { render, screen, within } from "@testing-library/react";
import { CapabilityOperationPanel } from "./CapabilityOperationPanel";

describe("capability operation readiness panel", () => {
  it("presents allocated query and command boundaries", () => {
    render(<CapabilityOperationPanel capabilityId="calculations" />);
    expect(screen.getByRole("heading", { name: "Capability operation readiness" })).toBeInTheDocument();
    const counts = screen.getByLabelText("Accepted operation counts");
    expect(within(counts).getByText("24")).toBeInTheDocument();
    expect(within(counts).getByText("13")).toBeInTheDocument();
    expect(within(counts).getByText("11")).toBeInTheDocument();
    expect(screen.getByText("Live transport inactive")).toBeInTheDocument();
    expect(screen.getByText(/Commands require explicit user or authorized-organisation approval/)).toBeInTheDocument();
  });

  it("presents an explicit no-operation state", () => {
    render(<CapabilityOperationPanel capabilityId="troubleshooting" />);
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getAllByText("No accepted operation")).toHaveLength(2);
    expect(screen.getByText("Protected content not loaded")).toBeInTheDocument();
  });
});
