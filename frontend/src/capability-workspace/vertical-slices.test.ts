import {
  CAPABILITY_VERTICAL_SLICES,
  getCapabilityVerticalSlice,
} from "./vertical-slices";

describe("evidence-led capability vertical slices", () => {
  it("defines every protected capability exactly once", () => {
    expect(CAPABILITY_VERTICAL_SLICES).toHaveLength(8);
    expect(new Set(CAPABILITY_VERTICAL_SLICES.map((item) => item.capabilityId)).size).toBe(8);
  });

  it("prepares only capabilities with accepted operations", () => {
    expect(CAPABILITY_VERTICAL_SLICES.filter(
      (item) => item.availability === "evidence_led_in_memory_ready",
    ).map((item) => item.capabilityId)).toEqual([
      "selection",
      "knowledge",
      "ingestion",
      "calculations",
      "designs",
    ]);
    expect(CAPABILITY_VERTICAL_SLICES.filter(
      (item) => item.availability === "no_accepted_backend_operation",
    ).map((item) => item.capabilityId)).toEqual([
      "troubleshooting",
      "projects",
      "security",
    ]);
  });

  it("preserves vendor-neutral and standards boundaries", () => {
    expect(getCapabilityVerticalSlice("selection")).toMatchObject({
      representativeQueryOperationKey: "get_api_v1_manufacturers",
      automaticBestBrandSelection: false,
      standardsConformityClaimed: false,
      liveTransportActive: false,
      protectedContentAvailable: false,
    });
    expect(getCapabilityVerticalSlice("calculations")).toMatchObject({
      representativeQueryOperationKey: "getAnalyzerTechnologyCatalogue",
      standardsConformityClaimed: false,
    });
  });
});
