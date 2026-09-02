import {
  createCapabilityOperationCatalogue,
  createCapabilityRequestPreview,
} from "./operations";

describe("capability operation presentation and request preview", () => {
  it("summarizes the exact protected operation allocation", () => {
    expect(createCapabilityOperationCatalogue("selection")).toMatchObject({
      state: "prepared_in_memory_contract_only",
      totalOperationCount: 22,
      queryOperationCount: 9,
      commandOperationCount: 13,
      liveTransportActive: false,
      automaticRetry: false,
      commandExecutionAutomatic: false,
    });
    expect(createCapabilityOperationCatalogue("troubleshooting")).toMatchObject({
      state: "no_accepted_backend_operation",
      totalOperationCount: 0,
      representativeQuery: null,
      representativeCommand: null,
    });
  });

  it("creates a query preview without authorizing execution", () => {
    expect(createCapabilityRequestPreview({
      capabilityId: "knowledge",
      operationKey: "get_api_v1_knowledge_summaries",
      operationMode: "query",
      input: { status: "verified" },
    })).toMatchObject({
      capabilityId: "knowledge",
      mode: "query",
      executionAuthorized: false,
      liveTransportActive: false,
      commandAuthorization: null,
    });
  });

  it("requires explicit authorization metadata for command previews", () => {
    expect(() => createCapabilityRequestPreview({
      capabilityId: "selection",
      operationKey: "post_api_v1_manufacturers",
      operationMode: "command",
      input: { name: "Example" },
    })).toThrow("requires explicit user or organisation authorization");

    expect(createCapabilityRequestPreview({
      capabilityId: "selection",
      operationKey: "post_api_v1_manufacturers",
      operationMode: "command",
      input: { name: "Example" },
      commandAuthorization: {
        authorized: true,
        reason: "The authorized product owner approved this in-memory request preview.",
        approvalOwner: "user_or_authorized_organisation",
      },
    })).toMatchObject({
      mode: "command",
      executionAuthorized: false,
      liveTransportActive: false,
      commandAuthorization: {
        authorized: true,
        approvalOwner: "user_or_authorized_organisation",
      },
    });
  });
});
