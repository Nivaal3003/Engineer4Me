import { render, screen } from "@testing-library/react";
import { AuthenticationActivationPanel } from "./AuthenticationActivationPanel";

describe("authentication activation readiness presentation", () => {
  it("shows missing external gates without offering a sign-in action", () => {
    render(<AuthenticationActivationPanel
      sourceReady={true}
      interactiveExecutionReady={false}
      missingGateLabels={["Delegated API permission consent proven", "Redirect URI registration proven"]}
      safeSummary="2 reviewed activation gates are not satisfied."
    />);
    expect(screen.getByRole("heading", { name: "Identity-provider activation gate" })).toBeInTheDocument();
    expect(screen.getByText("Blocked")).toBeInTheDocument();
    expect(screen.getByText("Delegated API permission consent proven")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/iu })).not.toBeInTheDocument();
  });
});
