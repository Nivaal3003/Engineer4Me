import {
  createNoDeploymentPermissionsPolicyHeaderEvidence,
  createReviewedDeploymentPermissionsPolicyHeaderEvidence,
} from "./deployment-header-evidence";

describe("deployment Permissions-Policy header evidence", () => {
  it("defaults to absent, desired-state-only evidence", () => {
    expect(createNoDeploymentPermissionsPolicyHeaderEvidence()).toMatchObject({
      source: "none",
      reviewCompleted: false,
      repositoryDesiredStateOnly: true,
      deploymentAppliedByBatch: false,
      productionDeploymentAuthorized: false,
      liveResponseHeaderRead: false,
      networkRequestPerformed: false,
    });
  });

  it("binds caller-supplied reviewed artifact evidence without reading a deployment", () => {
    expect(createReviewedDeploymentPermissionsPolicyHeaderEvidence({
      evidenceId: "deployment-header-fixture",
      source: "scripted_test_fixture",
      artifactSha256: "a".repeat(64),
      headerName: "permissions-policy",
      value: "microphone=(self), camera=(self)",
      reviewCompleted: true,
    })).toMatchObject({
      headerName: "Permissions-Policy",
      artifactSha256: "a".repeat(64),
      reviewCompleted: true,
      parsed: { state: "accepted" },
      deploymentAppliedByBatch: false,
      liveResponseHeaderRead: false,
    });
  });
});
