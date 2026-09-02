import {
  CapabilityAdapterError,
  INACTIVE_CAPABILITY_ADAPTER,
  validateCapabilityAdapterRequest,
} from "./adapter";

describe("protected capability adapter port", () => {
  it("accepts only operations allocated to the requested capability", () => {
    expect(() => validateCapabilityAdapterRequest({
      requestId: "request-1",
      capabilityId: "knowledge",
      operationKey: "get_api_v1_knowledge_summaries",
      input: { filter: "verified" },
    })).not.toThrow();
    expect(() => validateCapabilityAdapterRequest({
      requestId: "request-2",
      capabilityId: "selection",
      operationKey: "get_api_v1_knowledge_summaries",
      input: null,
    })).toThrow("not owned");
  });

  it("requires explicit user or organisation authorization for command operations", () => {
    const commandRequest = {
      requestId: "request-command-1",
      capabilityId: "selection",
      operationKey: "post_api_v1_manufacturers",
      input: { name: "Example manufacturer" },
    } as const;
    expect(() => validateCapabilityAdapterRequest(commandRequest)).toThrow(
      "explicit user or authorized-organisation command authorization",
    );
    expect(() => validateCapabilityAdapterRequest({
      ...commandRequest,
      commandAuthorization: {
        authorized: true,
        reason: "The authorized product owner approved this in-memory command contract fixture.",
        approvalOwner: "user_or_authorized_organisation",
      },
    })).not.toThrow();
  });

  it("fails closed when the running application adapter is inactive", async () => {
    await expect(INACTIVE_CAPABILITY_ADAPTER.execute({
      requestId: "request-3",
      capabilityId: "selection",
      operationKey: "get_api_v1_manufacturers",
      input: null,
    })).rejects.toMatchObject({
      kind: "adapter_unavailable",
      retryAutomatically: false,
    } satisfies Partial<CapabilityAdapterError>);
  });
});
