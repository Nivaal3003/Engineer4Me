import { Link } from "react-router";
import type { AuthenticationSnapshot } from "../auth/session";
import type { BackendAuthorizationProfileSourceReadiness } from "../auth/profile-source";
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
    <StateExperience
      action={<Link className="e4m-link-button" to="/">Return to workspace</Link>}
      model={model}
    />
  );
}
