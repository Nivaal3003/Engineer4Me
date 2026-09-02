import {
  CAPABILITY_RESULT_CONTROLS,
  createScriptedCapabilityAdapter,
  type ProtectedCapabilityId,
} from "../capabilities";
import { getCapabilityVerticalSlice } from "./vertical-slices";

type VerticalSliceCase = readonly [
  capabilityId: ProtectedCapabilityId,
  operationKey: string,
  title: string,
  revision: string,
];

const CASES: readonly VerticalSliceCase[] = Object.freeze([
  ["selection", "get_api_v1_manufacturers", "Selection catalogue", "phase9-step370-v1"],
  ["knowledge", "get_api_v1_knowledge_summaries", "Knowledge summaries", "phase9-step371-v1"],
  ["ingestion", "get_api_v1_ingestion_statistics", "Ingestion statistics", "phase9-step372-v1"],
  ["calculations", "getAnalyzerTechnologyCatalogue", "Calculation catalogue", "phase9-step373-v1"],
  ["designs", "listDesignCases", "Design cases", "phase9-step374-v1"],
]);

describe("five evidence-led in-memory vertical slices", () => {
  it("verifies every prepared slice through the strict result contract", async () => {
    for (const [capabilityId, operationKey, title, revision] of CASES) {
      const scripted = createScriptedCapabilityAdapter(capabilityId, [{
        kind: "result",
        value: {
          schemaVersion: 1,
          capabilityId,
          operationKey,
          state: "ready",
          value: {
            title,
            summary: `A bounded ${capabilityId} fixture demonstrates the Phase 9 vertical slice.`,
            itemCount: 1,
            payload: [{ fixtureId: `${capabilityId}-1`, state: "contract_only" }],
          },
          evidence: [{
            sourceId: `fixture:${capabilityId}:1`,
            title: `${title} fixture evidence`,
            revision: "1",
            locator: "unit-test",
          }],
          assumptions: ["The fixture is not a connected backend response."],
          limitations: ["No live capability request was made."],
          warnings: ["Final engineering approval remains external to this fixture."],
          confidence: "not_assessed",
          revision,
          approval: {
            status: "review_required",
            owner: "Engineer4Me product owner",
            approvedAt: null,
          },
          controls: CAPABILITY_RESULT_CONTROLS,
        },
      }]);
      const result = await scripted.adapter.execute({
        requestId: `vertical-slice-${capabilityId}-1`,
        capabilityId,
        operationKey,
        input: null,
      });
      expect(result).toMatchObject({
        capabilityId,
        operationKey,
        revision,
        controls: {
          vendorNeutrality: "required",
          standardsConformityClaim: "not_claimed",
        },
      });
      expect(scripted.networkRequestsPerformed).toBe(false);
      expect(getCapabilityVerticalSlice(capabilityId).availability)
        .toBe("evidence_led_in_memory_ready");
    }
  });

  it("keeps unsupported routes unavailable without inventing endpoints", () => {
    const unsupported: readonly ProtectedCapabilityId[] = [
      "troubleshooting",
      "projects",
      "security",
    ];
    for (const capabilityId of unsupported) {
      expect(getCapabilityVerticalSlice(capabilityId)).toMatchObject({
        availability: "no_accepted_backend_operation",
        representativeQueryOperationKey: null,
        liveTransportActive: false,
        protectedContentAvailable: false,
      });
    }
  });
});
