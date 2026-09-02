import {
  CAPABILITY_RESULT_CONTROLS,
  decodeCapabilityWorkspaceResult,
} from "../capabilities";
import { createCapabilityResultViewModel } from "./models";

const RESULT = decodeCapabilityWorkspaceResult({
  schemaVersion: 1,
  capabilityId: "calculations",
  operationKey: "getAnalyzerTechnologyCatalogue",
  state: "degraded",
  value: {
    title: "Analyzer technology catalogue",
    summary: "A bounded in-memory fixture demonstrates the evidence-led view contract.",
    itemCount: 2,
    payload: [{ technology: "example-a" }, { technology: "example-b" }],
  },
  evidence: [{
    sourceId: "fixture:calculations:analyzer-catalogue",
    title: "Analyzer catalogue contract fixture",
    revision: "1",
    locator: "unit-test",
  }],
  assumptions: ["The fixture is not a connected backend response."],
  limitations: ["No process application has been assessed."],
  warnings: ["Final technology selection requires application evidence and user approval."],
  confidence: "not_assessed",
  revision: "phase9-step368-v1",
  approval: {
    status: "review_required",
    owner: "Engineer4Me product owner",
    approvedAt: null,
  },
  controls: CAPABILITY_RESULT_CONTROLS,
}, {
  capabilityId: "calculations",
  operationKey: "getAnalyzerTechnologyCatalogue",
});

describe("capability result view model", () => {
  it("projects evidence and approval controls without activating transport", () => {
    expect(createCapabilityResultViewModel(RESULT)).toMatchObject({
      capabilityId: "calculations",
      operationKey: "getAnalyzerTechnologyCatalogue",
      state: "degraded",
      itemCountLabel: "2 items",
      confidenceLabel: "not assessed",
      approvalStatusLabel: "review required",
      sourceMode: "in_memory_contract_only",
      liveTransportActive: false,
      protectedContentSource: "scripted_in_memory_fixture",
      standardsBoundaryLabel: "No standards conformity claim",
      vendorNeutralityLabel: "Vendor neutrality required",
    });
  });

  it("retains traceable evidence and explicit limitations", () => {
    const view = createCapabilityResultViewModel(RESULT);
    expect(view.evidence).toEqual([{
      sourceId: "fixture:calculations:analyzer-catalogue",
      title: "Analyzer catalogue contract fixture",
      revisionLabel: "1",
      locatorLabel: "unit-test",
    }]);
    expect(view.limitations).toContain("No process application has been assessed.");
    expect(view.warnings).toContain(
      "Final technology selection requires application evidence and user approval.",
    );
  });
});
