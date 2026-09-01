import { render, screen } from "@testing-library/react";
import { PHASE_9_PRODUCT_BOUNDARIES } from "../foundation";
import { BoundaryNotice } from "./BoundaryNotice";

describe("Engineer4Me controlled product boundaries", () => {
  it("keeps vendor neutrality, proprietary identification, and approval ownership visible", () => {
    const selected = PHASE_9_PRODUCT_BOUNDARIES.filter((item) =>
      [
        "vendor_neutrality",
        "proprietary_and_trademark_identification",
        "engineering_and_operational_approval",
      ].includes(item.id),
    );
    render(<BoundaryNotice boundaries={selected} />);
    expect(screen.getByText("Vendor Neutrality")).toBeInTheDocument();
    expect(screen.getByText("Proprietary And Trademark Identification")).toBeInTheDocument();
    expect(screen.getByText("Engineering And Operational Approval")).toBeInTheDocument();
    expect(screen.getAllByText("required")).toHaveLength(3);
  });
});
