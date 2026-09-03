import { render, screen, within } from "@testing-library/react";
import { FieldInteractionPreview } from "./FieldInteractionPreview";

describe("scripted field-interaction preview presentation", () => {
  it("renders transcript, metadata, privacy, and review states without execution", () => {
    render(<FieldInteractionPreview capabilityId="calculations" />);
    expect(screen.getByRole("heading", {
      name: "Field interaction review preview",
    })).toBeInTheDocument();
    expect(screen.getByText(/Review the accepted evidence and available operations/))
      .toBeInTheDocument();
    expect(screen.getByText("Review required")).toBeInTheDocument();
    expect(screen.getByText("No operation selected")).toBeInTheDocument();
    const metadata = screen.getByRole("heading", {
      name: "Metadata-only multimodal descriptors",
    }).parentElement;
    expect(metadata).not.toBeNull();
    expect(within(metadata as HTMLElement).getAllByText("Raw content unavailable"))
      .toHaveLength(2);
    expect(screen.getByText(/No backend request, bearer-token attachment/))
      .toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
