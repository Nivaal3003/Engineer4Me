import {
  CAPABILITY_RESULT_CONTROLS,
  decodeCapabilityWorkspaceResult,
} from "./contracts";

function validResult() {
  return {
    schemaVersion: 1,
    capabilityId: "selection",
    operationKey: "get_api_v1_manufacturers",
    state: "ready",
    value: {
      title: "Manufacturer catalogue",
      summary: "One in-memory fixture record is available for contract verification.",
      itemCount: 1,
      payload: [{ manufacturerId: "fixture-manufacturer", name: "Example" }],
    },
    evidence: [
      {
        sourceId: "fixture:selection:manufacturers",
        title: "In-memory manufacturer contract fixture",
        revision: "1",
        locator: "test-only",
      },
    ],
    assumptions: ["The fixture is not a live backend response."],
    limitations: ["No product selection or brand preference is inferred."],
    warnings: ["Engineering approval remains external to this fixture."],
    confidence: "not_assessed",
    revision: "phase9-step362-v1",
    approval: {
      status: "unreviewed",
      owner: "Engineer4Me product owner",
      approvedAt: null,
    },
    controls: CAPABILITY_RESULT_CONTROLS,
  } as const;
}

describe("evidence-led capability result contract", () => {
  it("decodes an exact in-memory result and preserves product controls", () => {
    const result = decodeCapabilityWorkspaceResult(validResult(), {
      capabilityId: "selection",
      operationKey: "get_api_v1_manufacturers",
    });
    expect(result).toMatchObject({
      state: "ready",
      capabilityId: "selection",
      operationKey: "get_api_v1_manufacturers",
      controls: {
        vendorNeutrality: "required",
        standardsConformityClaim: "not_claimed",
        bestBrandDecisionOwner: "user_or_authorized_organisation",
      },
    });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("rejects unexpected fields and cross-capability operation ownership", () => {
    expect(() => decodeCapabilityWorkspaceResult(
      { ...validResult(), unexpected: "not allowed" },
      { capabilityId: "selection", operationKey: "get_api_v1_manufacturers" },
    )).toThrow("unexpected field");
    expect(() => decodeCapabilityWorkspaceResult(validResult(), {
      capabilityId: "knowledge",
      operationKey: "get_api_v1_manufacturers",
    })).toThrow("ownership differs");
  });

  it("rejects evidence-free, non-finite, and unsupported product claims", () => {
    expect(() => decodeCapabilityWorkspaceResult(
      { ...validResult(), evidence: [] },
      { capabilityId: "selection", operationKey: "get_api_v1_manufacturers" },
    )).toThrow("between 1 and 50");
    expect(() => decodeCapabilityWorkspaceResult(
      { ...validResult(), value: { ...validResult().value, payload: Number.NaN } },
      { capabilityId: "selection", operationKey: "get_api_v1_manufacturers" },
    )).toThrow("finite plain JSON");
    expect(() => decodeCapabilityWorkspaceResult(
      {
        ...validResult(),
        controls: { ...CAPABILITY_RESULT_CONTROLS, standardsConformityClaim: "claimed" },
      },
      { capabilityId: "selection", operationKey: "get_api_v1_manufacturers" },
    )).toThrow("standardsConformityClaim differs");
  });
});
