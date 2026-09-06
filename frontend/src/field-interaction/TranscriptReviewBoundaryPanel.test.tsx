import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { TranscriptReviewBoundaryPanel } from "./TranscriptReviewBoundaryPanel";
describe("transcript provenance boundary panel", () => {
  it("uses the heading-derived accessible name and exposes no live or review control", () => {
    render(<TranscriptReviewBoundaryPanel />);
    const region = screen.getByRole("region", { name: "Transcript provenance and revision review" });
    expect(region).toHaveAttribute("aria-labelledby", "transcript-review-boundary-heading");
    expect(within(region).getByText(/No live transcription is available/)).toBeInTheDocument();
    expect(within(region).getByText(/Local preview only/)).toBeInTheDocument();
    expect(within(region).queryByRole("button")).not.toBeInTheDocument();
    expect(within(region).queryByRole("textbox")).not.toBeInTheDocument();
  });
});
