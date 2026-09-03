import { render, screen } from "@testing-library/react";
import { PermissionCapabilityPanel } from "./PermissionCapabilityPanel";

describe("permission capability evidence presentation", () => {
  it("presents read-only detection and no-prompt boundaries accessibly", () => {
    render(<PermissionCapabilityPanel />);
    expect(screen.getByRole("heading", { name: "Permission capability evidence" })).toBeInTheDocument();
    expect(screen.getByText("Read-only detection")).toBeInTheDocument();
    expect(screen.getByText("No permission prompt")).toBeInTheDocument();
    expect(screen.getByText("Not enumerated")).toBeInTheDocument();
    expect(screen.getByText(/does not grant permission or authorize capture/)).toBeInTheDocument();
  });
});
