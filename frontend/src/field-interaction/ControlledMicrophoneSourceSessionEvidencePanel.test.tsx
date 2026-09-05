import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ControlledMicrophoneSourceSessionEvidencePanel } from "./ControlledMicrophoneSourceSessionEvidencePanel";

describe("controlled microphone source-session evidence panel", () => {
  it("presents the bounded verifier evidence without an application activation control", () => {
    render(<ControlledMicrophoneSourceSessionEvidencePanel />);
    expect(screen.getByRole("heading", { name: "Controlled microphone source-session evidence" })).toBeInTheDocument();
    expect(screen.getByText("One source session maximum")).toBeInTheDocument();
    expect(screen.getByText("Three-second source ceiling")).toBeInTheDocument();
    expect(screen.getByText("Audio samples remain inaccessible")).toBeInTheDocument();
    const boundary = screen.getByLabelText("Controlled microphone source-session boundary");
    expect(within(boundary).getByText("3 seconds")).toBeInTheDocument();
    expect(within(boundary).getByText("2 seconds")).toBeInTheDocument();
    expect(within(boundary).getByText("Separate audio-sample intervention")).toBeInTheDocument();
    expect(within(boundary).getByText("Unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
