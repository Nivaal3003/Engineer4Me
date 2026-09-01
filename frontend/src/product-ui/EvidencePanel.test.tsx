import { render, screen } from "@testing-library/react";
import type { EngineeringEvidenceViewModel } from "../foundation";
import { EvidencePanel } from "./EvidencePanel";

const model: EngineeringEvidenceViewModel = {
  evidence: [],
  confidence: { level: "unknown", basis: ["No connected result is displayed."] },
  assumptions: ["No process data has been supplied."],
  limitations: ["API transport remains inactive."],
  warnings: ["Do not treat this shell as engineering approval."],
  revision: { revision: "Phase 9 shell foundation", status: "draft", owner: "Engineer4Me product owner" },
  standardsConformityClaim: "not_claimed",
  finalEngineeringApprovalOwner: "user_or_authorized_organisation",
};

describe("Engineer4Me evidence presentation", () => {
  it("shows evidence gaps, limitations, warnings, and approval ownership", () => {
    render(<EvidencePanel model={model} />);
    expect(screen.getByText("No process data has been supplied.")).toBeInTheDocument();
    expect(screen.getByText("API transport remains inactive.")).toBeInTheDocument();
    expect(screen.getByText("Do not treat this shell as engineering approval.")).toBeInTheDocument();
    expect(screen.getByText("No standards conformity claim")).toBeInTheDocument();
    expect(screen.getByText(/Final engineering approval remains/)).toBeInTheDocument();
  });
});
