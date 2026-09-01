import { render, screen } from "@testing-library/react";
import { Button, SectionHeading, StatusBadge, VisuallyHidden } from "./primitives";

describe("Engineer4Me accessible primitives", () => {
  it("uses a non-submitting button default and preserves accessible naming", () => {
    render(<Button variant="primary">Review evidence</Button>);
    const button = screen.getByRole("button", { name: "Review evidence" });
    expect(button).toHaveAttribute("type", "button");
    expect(button).toHaveClass("e4m-button--primary");
  });

  it("renders labelled section and status primitives", () => {
    render(
      <>
        <SectionHeading
          eyebrow="Controlled status"
          headingId="status-heading"
          title="Product readiness"
        />
        <StatusBadge tone="warning">Not connected</StatusBadge>
        <VisuallyHidden>Additional context</VisuallyHidden>
      </>,
    );
    expect(screen.getByRole("heading", { name: "Product readiness" })).toHaveAttribute(
      "id",
      "status-heading",
    );
    expect(screen.getByText("Not connected")).toHaveClass("status-badge--warning");
    expect(screen.getByText("Additional context")).toHaveClass("visually-hidden");
  });
});
