import { render, screen } from "@testing-library/react";
import { OrganisationProfilePanel } from "./OrganisationProfilePanel";

describe("organisation profile transport presentation", () => {
  it("shows the absent accepted backend profile operation explicitly", () => {
    render(<OrganisationProfilePanel
      sourceState="unavailable"
      sourceReason="No accepted backend authorization-profile operation"
      profileLabel="Not loaded"
      organisationLabel="Not selected"
    />);
    expect(screen.getByRole("heading", { name: "Organisation and access profile transport" })).toBeInTheDocument();
    expect(screen.getByText("No accepted backend authorization-profile operation")).toBeInTheDocument();
    expect(screen.getByText(/No profile endpoint is inferred/u)).toBeInTheDocument();
  });
});
