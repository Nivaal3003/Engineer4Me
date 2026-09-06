import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ScriptedProcessingBoundaryPanel } from "./ScriptedProcessingBoundaryPanel";
describe("scripted processing boundary presentation", () => {
  it("presents inert status under its actual heading-derived accessible name", () => {
    render(<ScriptedProcessingBoundaryPanel />);
    const region = screen.getByRole("region", { name: "Scripted processing lifecycle boundary" });
    expect(region).toHaveAttribute("aria-labelledby", "scripted-processing-boundary-heading");
    expect(within(region).getByText("Separate draft review required; never automatic execution")).toBeInTheDocument();
    expect(within(region).getByText("16")).toBeInTheDocument();
    expect(within(region).queryByRole("button")).not.toBeInTheDocument();
    expect(within(region).queryByRole("textbox")).not.toBeInTheDocument();
  });
});
