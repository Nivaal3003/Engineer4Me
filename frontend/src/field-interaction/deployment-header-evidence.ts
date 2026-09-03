import { validateFieldInteractionIdentifier } from "./models";
import {
  parseDeploymentPermissionsPolicyValue,
  PERMISSIONS_POLICY_HEADER_NAME,
  type DeploymentPermissionsPolicyParseResult,
} from "./deployment-permissions-policy";

export type DeploymentHeaderEvidenceSource =
  | "none"
  | "reviewed_deployment_artifact"
  | "scripted_test_fixture";

export interface DeploymentPermissionsPolicyHeaderEvidence {
  readonly evidenceId: string | null;
  readonly source: DeploymentHeaderEvidenceSource;
  readonly artifactSha256: string | null;
  readonly headerName: typeof PERMISSIONS_POLICY_HEADER_NAME | null;
  readonly suppliedValue: string | null;
  readonly reviewCompleted: boolean;
  readonly parsed: DeploymentPermissionsPolicyParseResult;
  readonly repositoryDesiredStateOnly: boolean;
  readonly deploymentAppliedByBatch: false;
  readonly productionDeploymentAuthorized: false;
  readonly liveResponseHeaderRead: false;
  readonly networkRequestPerformed: false;
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export function createNoDeploymentPermissionsPolicyHeaderEvidence():
  DeploymentPermissionsPolicyHeaderEvidence {
  return Object.freeze({
    evidenceId: null,
    source: "none",
    artifactSha256: null,
    headerName: null,
    suppliedValue: null,
    reviewCompleted: false,
    parsed: parseDeploymentPermissionsPolicyValue(null),
    repositoryDesiredStateOnly: true,
    deploymentAppliedByBatch: false,
    productionDeploymentAuthorized: false,
    liveResponseHeaderRead: false,
    networkRequestPerformed: false,
  });
}

export function createReviewedDeploymentPermissionsPolicyHeaderEvidence(input: {
  readonly evidenceId: string;
  readonly source: Exclude<DeploymentHeaderEvidenceSource, "none">;
  readonly artifactSha256: string;
  readonly headerName: string;
  readonly value: string;
  readonly reviewCompleted: boolean;
}): DeploymentPermissionsPolicyHeaderEvidence {
  const artifactSha256 = input.artifactSha256.trim().toLowerCase();
  if (!SHA256_PATTERN.test(artifactSha256)) {
    throw new Error(
      "Deployment header evidence SHA-256 must be exactly 64 lowercase hexadecimal characters.",
    );
  }
  if (input.headerName.trim().toLowerCase() !== "permissions-policy") {
    throw new Error("Deployment header evidence must bind the Permissions-Policy header.");
  }
  return Object.freeze({
    evidenceId: validateFieldInteractionIdentifier(
      input.evidenceId,
      "Deployment header evidence identifier",
    ),
    source: input.source,
    artifactSha256,
    headerName: PERMISSIONS_POLICY_HEADER_NAME,
    suppliedValue: input.value.trim(),
    reviewCompleted: input.reviewCompleted,
    parsed: parseDeploymentPermissionsPolicyValue(input.value),
    repositoryDesiredStateOnly: input.source === "reviewed_deployment_artifact",
    deploymentAppliedByBatch: false,
    productionDeploymentAuthorized: false,
    liveResponseHeaderRead: false,
    networkRequestPerformed: false,
  });
}
