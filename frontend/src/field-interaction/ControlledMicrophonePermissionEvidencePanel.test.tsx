import { render, screen } from "@testing-library/react";
import { ControlledMicrophonePermissionEvidencePanel } from "./ControlledMicrophonePermissionEvidencePanel";

describe("controlled microphone permission evidence panel", () => {
  it("presents the one-request and immediate-stop boundary without an application control", () => {
    render(<ControlledMicrophonePermissionEvidencePanel />);
    expect(
      screen.getByRole("heading", {
        name: "Controlled microphone permission request evidence",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("One request maximum")).toBeInTheDocument();
    expect(screen.getByText("Brief microphone activation disclosed")).toBeInTheDocument();
    expect(screen.getByText("Immediate track stop required")).toBeInTheDocument();
    expect(screen.getByText("Application request control unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
