import {
  getProtectedCapabilityAdapterDefinition,
  PROTECTED_CAPABILITY_ADAPTER_DEFINITIONS,
} from "./registry";

describe("protected capability adapter registry", () => {
  it("prepares five evidence-led adapters and leaves unsupported routes unavailable", () => {
    expect(PROTECTED_CAPABILITY_ADAPTER_DEFINITIONS.filter(
      (item) => item.state === "prepared_in_memory_contract_only",
    )).toHaveLength(5);
    expect(PROTECTED_CAPABILITY_ADAPTER_DEFINITIONS.filter(
      (item) => item.state === "no_accepted_backend_operation",
    ).map((item) => item.capabilityId)).toEqual([
      "troubleshooting",
      "projects",
      "security",
    ]);
  });

  it("never activates transport, retries, or protected content", () => {
    for (const definition of PROTECTED_CAPABILITY_ADAPTER_DEFINITIONS) {
      expect(definition.liveTransportActive).toBe(false);
      expect(definition.automaticRetry).toBe(false);
      expect(definition.protectedContentAvailable).toBe(false);
    }
    expect(getProtectedCapabilityAdapterDefinition("calculations"))
      .toMatchObject({ operationCount: 24, queryOperationCount: 13, commandOperationCount: 11 });
  });
});
