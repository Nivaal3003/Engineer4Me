import { createInertControlledMicrophonePermissionAdapter } from "./inert-controlled-microphone-permission-adapter";

describe("inert controlled microphone permission adapter", () => {
  it("exposes no application permission, device, capture, transport, or AI operation", () => {
    const adapter = createInertControlledMicrophonePermissionAdapter();
    expect(adapter.permissionRequestOperationAvailable).toBe(false);
    expect(adapter.permissionStatusQueryOperationAvailable).toBe(false);
    expect(adapter.deviceEnumerationOperationAvailable).toBe(false);
    expect(adapter.captureOperationAvailable).toBe(false);
    expect(adapter.backendTransportOperationAvailable).toBe(false);
    expect(adapter.externalAiOperationAvailable).toBe(false);
    expect(adapter.counters).toEqual({
      permissionRequests: 0,
      permissionStatusQueries: 0,
      deviceEnumerations: 0,
      trackConsumers: 0,
      recordings: 0,
      persistedMedia: 0,
      transmittedMedia: 0,
    });
  });
});
