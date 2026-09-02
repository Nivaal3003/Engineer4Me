import { CAPABILITY_RESULT_CONTROLS } from "./contracts";
import { createScriptedCapabilityAdapter } from "./testing";

function fixture() {
  return {
    schemaVersion: 1,
    capabilityId: "knowledge",
    operationKey: "get_api_v1_knowledge_summaries",
    state: "ready",
    value: {
      title: "Verified knowledge summaries",
      summary: "One in-memory summary is available.",
      itemCount: 1,
      payload: [{ knowledgeId: "fixture-1", status: "verified" }],
    },
    evidence: [{
      sourceId: "fixture:knowledge:verified",
      title: "In-memory verified-knowledge fixture",
      revision: "1",
      locator: "unit-test",
    }],
    assumptions: ["The fixture is not a connected repository result."],
    limitations: ["No live knowledge operation was executed."],
    warnings: ["The user must verify applicability before engineering use."],
    confidence: "not_assessed",
    revision: "phase9-step363-v1",
    approval: { status: "unreviewed", owner: "Engineer4Me product owner", approvedAt: null },
    controls: CAPABILITY_RESULT_CONTROLS,
  } as const;
}

describe("scripted in-memory capability adapter", () => {
  it("verifies the result contract without network activity or retries", async () => {
    const scripted = createScriptedCapabilityAdapter("knowledge", [
      { kind: "result", value: fixture() },
    ]);
    const result = await scripted.adapter.execute({
      requestId: "knowledge-fixture-1",
      capabilityId: "knowledge",
      operationKey: "get_api_v1_knowledge_summaries",
      input: { status: "verified" },
    });
    expect(result.value.itemCount).toBe(1);
    expect(scripted.calls).toHaveLength(1);
    expect(scripted.remaining()).toBe(0);
    expect(scripted.networkRequestsPerformed).toBe(false);
    expect(scripted.adapter.automaticRetry).toBe(false);
    expect(scripted.adapter.liveTransportActive).toBe(false);
  });

  it("fails closed when the script is exhausted", async () => {
    const scripted = createScriptedCapabilityAdapter("knowledge", []);
    await expect(scripted.adapter.execute({
      requestId: "knowledge-fixture-2",
      capabilityId: "knowledge",
      operationKey: "get_api_v1_knowledge_summaries",
      input: null,
    })).rejects.toMatchObject({
      kind: "script_exhausted",
      retryAutomatically: false,
    });
  });
});
