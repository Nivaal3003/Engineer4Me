import { render, screen } from "@testing-library/react";
import { AuthenticationSummary } from "./AuthenticationSummary";

describe("authentication access summary", () => {
  it("presents explicit configuration, identity, authorization, organisation, and token states", () => {
    render(<AuthenticationSummary
      phaseLabel="Configured, inactive"
      configurationLabel="Ready"
      identityLabel="Not established"
      authorizationLabel="Not loaded"
      organisationLabel="Not selected"
      roleCount={0}
      entitlementCount={0}
      tokenAttachmentLabel="Inactive"
    />);
    expect(screen.getByRole("heading", { name: "Authentication and access status" })).toBeInTheDocument();
    expect(screen.getByText("Configured, inactive")).toBeInTheDocument();
    expect(screen.getByText(/Backend authorization remains authoritative/u)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in/iu })).not.toBeInTheDocument();
  });
});
