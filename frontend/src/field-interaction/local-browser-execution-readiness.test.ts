import { createControlledLocalBrowserExecutionPolicy } from "./local-browser-execution-policy";
import {
  createNoLocalBrowserExecutableEvidence,
  createReviewedLocalBrowserExecutableEvidence,
  evaluateLocalBrowserExecutionReadiness,
} from "./local-browser-execution-readiness";
import { createControlledLoopbackResponseObservation } from "./loopback-response-observation";

function acceptedObservation() {
  return createControlledLoopbackResponseObservation({
    observationId: "accepted-loopback-observation",
    source: "scripted_test_fixture",
    requestMethod: "GET",
    requestUrl: "http://127.0.0.1:43127/phase10-readiness",
    statusCode: 200,
    headers: [
      { name: "Content-Type", value: "text/html; charset=utf-8" },
      { name: "Cache-Control", value: "no-store" },
      { name: "Permissions-Policy", value: "microphone=(), camera=()" },
    ],
  });
}

describe("local browser execution readiness", () => {
  it("requires a controlled loopback observation before any launch gate", () => {
    expect(evaluateLocalBrowserExecutionReadiness({
      observation: null,
      executableEvidence: createNoLocalBrowserExecutableEvidence(),
      policy: createControlledLocalBrowserExecutionPolicy(),
    })).toMatchObject({
      state: "loopback_observation_required",
      browserLaunchAuthorized: false,
      browserExecuted: false,
    });
  });

  it("requires reviewed executable evidence without collecting browser identity", () => {
    expect(evaluateLocalBrowserExecutionReadiness({
      observation: acceptedObservation(),
      executableEvidence: createNoLocalBrowserExecutableEvidence(),
      policy: createControlledLocalBrowserExecutionPolicy(),
    })).toMatchObject({
      state: "browser_executable_evidence_required",
      exactDefaultDenyHeaderObserved: true,
      browserNameCollected: false,
      browserVersionCollected: false,
      userAgentRead: false,
    });
  });

  it("reaches only the separate intervention gate when all evidence is accepted", () => {
    expect(evaluateLocalBrowserExecutionReadiness({
      observation: acceptedObservation(),
      executableEvidence: createReviewedLocalBrowserExecutableEvidence({
        evidenceId: "browser-executable-fixture",
        source: "scripted_test_fixture",
        executableFilePresent: true,
        executableSha256: "c".repeat(64),
        reviewCompleted: true,
      }),
      policy: createControlledLocalBrowserExecutionPolicy(),
    })).toMatchObject({
      state: "intervention_required",
      candidateForControlledBrowserExecutionGate: true,
      loopbackObservationAccepted: true,
      executableEvidenceAccepted: true,
      executionPolicyAccepted: true,
      browserLaunchAuthorized: false,
      browserExecuted: false,
      permissionStatusQueried: false,
      permissionPromptShown: false,
      backendTransportActivated: false,
      protectedContentAccessed: false,
    });
  });
});
