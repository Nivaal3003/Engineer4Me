import { render, screen } from "@testing-library/react";
import { PermissionGesturePolicyPanel } from "./PermissionGesturePolicyPanel";

describe("explicit user-gesture policy presentation", () => {
  it("shows the intervention boundary without an activation control", () => {
    render(<PermissionGesturePolicyPanel capabilityId="selection" />);
    expect(screen.getByRole("heading", { name: "User-gesture activation policy" })).toBeInTheDocument();
    expect(screen.getByText("Trusted gesture required")).toBeInTheDocument();
    expect(screen.getByText("Intervention gate closed")).toBeInTheDocument();
    expect(screen.getByText("Maximum 5 seconds")).toBeInTheDocument();
    expect(screen.getByText("Single use only")).toBeInTheDocument();
    expect(screen.getAllByText("No")).toHaveLength(2);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
