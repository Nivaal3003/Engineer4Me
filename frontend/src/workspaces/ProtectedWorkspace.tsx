import { Link } from "react-router";
import type { AuthenticationSnapshot } from "../auth/session";
import type { BackendAuthorizationProfileSourceReadiness } from "../auth/profile-source";
import { CapabilityOperationPanel } from "../capability-workspace";
import {
  ControlledAudioSampleAcquisitionProposalPanel,
  ControlledBrowserCapabilityObservationPanel,
  ControlledBrowserNavigationEvidencePanel,
  ControlledMicrophoneCaptureProposalPanel,
  ControlledMicrophoneSourceSessionEvidencePanel,
  ControlledMicrophonePermissionEvidencePanel,
  FieldInteractionPreview,
  LocalBrowserExecutionReadinessPanel,
  MicrophonePermissionActivationProposalPanel,
  FieldInteractionReadinessPanel,
  PermissionCapabilityPanel,
  PermissionGesturePolicyPanel,
  SupportedBrowserReadinessPanel,
} from "../field-interaction";
import type { AppRouteDefinition, RouteAccessContext } from "../routing";
import { createStateExperience, StateExperience } from "../state-experience";
import { createProtectedWorkspaceModel } from "./models";

export interface ProtectedWorkspaceProps {
  readonly route: AppRouteDefinition;
  readonly accessContext: RouteAccessContext;
  readonly authentication: AuthenticationSnapshot;
  readonly profileSource: BackendAuthorizationProfileSourceReadiness;
  readonly apiTransportActive: boolean;
}

export function ProtectedWorkspace(props: ProtectedWorkspaceProps) {
  if (props.route.id === "home") {
    throw new Error("The public home route cannot render a protected workspace.");
  }
  const workspace = createProtectedWorkspaceModel(props);
  const model = createStateExperience(
    workspace.state === "entitlement_denied" ? "error" : "unavailable",
    {
      eyebrow: "Protected workspace",
      title: workspace.title,
      detail: workspace.detail,
      guidance: workspace.guidance,
      retryAuthorized: false,
    },
  );
  return (
    <div className="protected-workspace">
      <StateExperience
        action={<Link className="e4m-link-button" to="/">Return to workspace</Link>}
        model={model}
      />
      <CapabilityOperationPanel capabilityId={props.route.id} />
      <FieldInteractionReadinessPanel capabilityId={props.route.id} />
      <PermissionCapabilityPanel />
      <PermissionGesturePolicyPanel capabilityId={props.route.id} />
      <SupportedBrowserReadinessPanel />
      <LocalBrowserExecutionReadinessPanel />
      <ControlledBrowserNavigationEvidencePanel />
      <ControlledBrowserCapabilityObservationPanel />
      <MicrophonePermissionActivationProposalPanel />
      <ControlledMicrophonePermissionEvidencePanel />
      <ControlledMicrophoneCaptureProposalPanel />
      <ControlledMicrophoneSourceSessionEvidencePanel />
      <ControlledAudioSampleAcquisitionProposalPanel />
      <FieldInteractionPreview capabilityId={props.route.id} />
    </div>
  );
}
