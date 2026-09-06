import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { ProcessingEvidenceBoundaryPanel } from "./ProcessingEvidenceBoundaryPanel";
describe("processing evidence boundary panel", () => {
  it("uses its heading as the accessible name and exposes no active controls", () => {
    render(<ProcessingEvidenceBoundaryPanel />);
    const region = screen.getByRole("region", { name: "Processing evidence and scope boundary" });
    expect(region).toHaveAttribute("aria-labelledby", "processing-evidence-boundary-heading");
    expect(within(region).getByText(/Declared review references do not verify their contents/)).toBeInTheDocument();
    expect(within(region).getByText("Required review categories")).toBeInTheDocument();
    expect(within(region).queryByRole("button")).not.toBeInTheDocument();
    expect(within(region).queryByRole("textbox")).not.toBeInTheDocument();
    expect(within(region).queryByRole("combobox")).not.toBeInTheDocument();
  });
});
