import { describe, expect, it } from "vitest";
import { evaluateControlledSignalPresenceReadiness } from "./controlled-audio-signal-presence-policy";

describe("controlled audio signal-presence readiness", () => {
  it("retains the verifier intervention gate after consent and a trusted gesture", () => {
    expect(evaluateControlledSignalPresenceReadiness({
      acceptedProposalBound: true,
      sampleSpecificConsentRecorded: true,
      trustedSingleUseGestureRecorded: true,
      currentPermissionStateInferred: false,
      applicationOperationAvailable: false,
    })).toEqual({
      state: "intervention_required",
      executionInterventionRequired: true,
      executionAuthorized: false,
      applicationOperationAvailable: false,
      currentPermissionStateInferred: false,
    });
  });

  it("fails closed when an application operation is exposed", () => {
    expect(() => evaluateControlledSignalPresenceReadiness({
      acceptedProposalBound: true,
      sampleSpecificConsentRecorded: true,
      trustedSingleUseGestureRecorded: true,
      currentPermissionStateInferred: false,
      applicationOperationAvailable: true,
    })).toThrow(/activation boundary differs/i);
  });
});
