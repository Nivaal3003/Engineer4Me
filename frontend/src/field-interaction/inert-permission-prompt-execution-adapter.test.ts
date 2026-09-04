import { createInertPermissionPromptExecutionAdapter } from "./inert-permission-prompt-execution-adapter";

describe("inert permission prompt execution adapter", () => {
  it("exposes no consent, gesture, prompt, device, capture, transport, or AI operation", () => {
    const adapter = createInertPermissionPromptExecutionAdapter();
    expect(adapter.permissionPromptExecutionOperationAvailable).toBe(false);
    expect(adapter.consentRecordingOperationAvailable).toBe(false);
    expect(adapter.trustedGestureRecordingOperationAvailable).toBe(false);
    expect(adapter.permissionStatusQueryOperationAvailable).toBe(false);
    expect(adapter.deviceEnumerationOperationAvailable).toBe(false);
    expect(adapter.captureOperationAvailable).toBe(false);
    expect(adapter.backendTransportOperationAvailable).toBe(false);
    expect(adapter.externalAiOperationAvailable).toBe(false);
    expect(adapter.counters.permissionPromptsExecuted).toBe(0);
  });
});
