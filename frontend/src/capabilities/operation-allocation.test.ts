import { BACKEND_OPERATIONS } from "../api/operation-registry";
import {
  getCapabilityOperationAllocations,
  getCapabilityOperationAllocationByKey,
  PROTECTED_CAPABILITY_IDS,
  PROTECTED_OPERATION_ALLOCATIONS,
} from "./operation-allocation";

const EXPECTED_COUNTS = Object.freeze({
  selection: 22,
  troubleshooting: 0,
  knowledge: 16,
  ingestion: 12,
  calculations: 24,
  designs: 17,
  projects: 0,
  security: 0,
});

describe("protected capability operation allocation", () => {
  it("allocates every protected backend operation exactly once", () => {
    const protectedOperations = BACKEND_OPERATIONS.filter(
      (operation) => operation.frontendAccessPolicy === "authenticated",
    );
    expect(protectedOperations).toHaveLength(91);
    expect(PROTECTED_OPERATION_ALLOCATIONS).toHaveLength(91);
    expect(new Set(PROTECTED_OPERATION_ALLOCATIONS.map((item) => item.operationKey)).size)
      .toBe(91);
    expect(PROTECTED_OPERATION_ALLOCATIONS.map((item) => item.operationKey).sort())
      .toEqual(protectedOperations.map((item) => item.key).sort());
  });

  it("uses the exact evidence-led capability counts", () => {
    for (const capabilityId of PROTECTED_CAPABILITY_IDS) {
      expect(getCapabilityOperationAllocations(capabilityId)).toHaveLength(
        EXPECTED_COUNTS[capabilityId],
      );
    }
  });

  it("keeps public operations outside protected adapters", () => {
    expect(BACKEND_OPERATIONS.filter((operation) => operation.frontendAccessPolicy === "public"))
      .toHaveLength(2);
    expect(PROTECTED_OPERATION_ALLOCATIONS.some((item) => item.pathTemplate === "/"))
      .toBe(false);
    expect(PROTECTED_OPERATION_ALLOCATIONS.some((item) => item.pathTemplate === "/health"))
      .toBe(false);
  });

  it("retains exact operation source traceability", () => {
    expect(getCapabilityOperationAllocationByKey("post_api_v1_selections"))
      .toMatchObject({
        capabilityId: "selection",
        method: "POST",
        mode: "command",
        pathTemplate: "/api/v1/selections",
        source: "backend/app/api/selections.py",
      });
  });
});
