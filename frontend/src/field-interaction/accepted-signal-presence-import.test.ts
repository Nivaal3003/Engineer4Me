import { describe, expect, it } from "vitest";
import { ACCEPTED_SIGNAL_EVIDENCE, importAcceptedSignalPresence } from "./accepted-signal-presence-import";
describe("accepted historical signal evidence", () => {
  it("imports only the accepted historical result without a transcript or permission inference", () => {
    const result = importAcceptedSignalPresence({ ...ACCEPTED_SIGNAL_EVIDENCE });
    expect(result.archiveBytesVerifiedByThisFunction).toBe(false);
    expect(result.receiptBytesVerifiedByThisFunction).toBe(false);
    expect(result.currentPermissionState).toBe("unknown");
    expect(result.microphoneFailureEstablished).toBe(false);
    expect(result.speechAbsenceEstablished).toBe(false);
    expect(result.transcriptAvailableFromSignalResult).toBe(false);
    expect(result.newCaptureAuthorized).toBe(false);
  });
  it("rejects every substituted identity and extra content", () => {
    for (const key of Object.keys(ACCEPTED_SIGNAL_EVIDENCE)) {
      expect(() => importAcceptedSignalPresence({ ...ACCEPTED_SIGNAL_EVIDENCE, [key]: "mismatch" })).toThrow(/identity differs/i);
    }
    expect(() => importAcceptedSignalPresence({ ...ACCEPTED_SIGNAL_EVIDENCE, text: "invented words" })).toThrow(/inventory/i);
    expect(() => importAcceptedSignalPresence(null)).toThrow();
  });
});
