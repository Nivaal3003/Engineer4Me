import { render, screen } from "@testing-library/react";
import { FieldInteractionReadinessPanel } from "./FieldInteractionReadinessPanel";

describe("field-interaction readiness presentation", () => {
  it("presents inactive permission and external-processing boundaries accessibly", () => {
    render(<FieldInteractionReadinessPanel capabilityId="selection" />);
    expect(screen.getByRole("heading", {
      name: "Voice and multimodal readiness",
    })).toBeInTheDocument();
    expect(screen.getByText("Microphone inactive")).toBeInTheDocument();
    expect(screen.getByText("Camera inactive")).toBeInTheDocument();
    expect(screen.getByText("External AI inactive")).toBeInTheDocument();
    expect(screen.getAllByText("inactive_not_requested")).toHaveLength(2);
    expect(screen.getByText(/No browser permission API/)).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
