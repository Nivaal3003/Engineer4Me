import { Link, Route, Routes, useLocation } from "react-router";
import {
  authenticationPhaseLabel,
  createAuthenticationRedirectPolicy,
  createInitialAuthenticationSnapshot,
  evaluateAuthenticationActivationReadiness,
  evaluateBackendAuthorizationProfileSource,
  NO_AUTHENTICATION_ACTIVATION_EVIDENCE,
  readAuthenticationConfiguration,
  type AuthenticationActivationReadiness,
  type AuthenticationSnapshot,
  type BackendAuthorizationProfileSourceReadiness,
} from "./auth";
import { INITIAL_PRODUCT_STATUS, PHASE_9_PRODUCT_BOUNDARIES, type EngineeringEvidenceViewModel } from "./foundation";
import { SectionHeading, StatusBadge } from "./design-system";
import {
  AccessAuditPanel,
  AuthenticationActivationPanel,
  AuthenticationSummary,
  BoundaryNotice,
  EvidencePanel,
  OrganisationProfilePanel,
  StatusSummary,
} from "./product-ui";
import { APP_ROUTES, createRouteAccessContext, routeById } from "./routing";
import { AppShell } from "./shell";
import { createStateExperience, StateExperience } from "./state-experience";
import { ProtectedWorkspace } from "./workspaces";

const SHELL_EVIDENCE: EngineeringEvidenceViewModel = {
  evidence: [],
  confidence: { level: "unknown", basis: ["No connected engineering result is displayed by this browser shell."] },
  assumptions: [],
  limitations: [
    "Authentication activation, backend authorization-profile transport, API transport activation, and engineering capability integration remain inactive.",
  ],
  warnings: [
    "Do not treat a route, access-state surface, or product shell as engineering approval or operational authorization.",
  ],
  revision: { revision: "Phase 9 authentication activation readiness", status: "draft", owner: "Engineer4Me product owner" },
  standardsConformityClaim: "not_claimed",
  finalEngineeringApprovalOwner: "user_or_authorized_organisation",
};

const VISIBLE_BOUNDARY_IDS = new Set([
  "vendor_neutrality",
  "standards_conformity",
  "proprietary_and_trademark_identification",
  "engineering_and_operational_approval",
  "service_worker_and_pwa_caching",
  "voice_functionality",
]);
const HOME_ROUTE = routeById("home");
const PROTECTED_ROUTES = APP_ROUTES.filter((route) => route.id !== "home");
const GATE_LABELS: Readonly<Record<string, string>> = {
  public_configuration_valid: "Public authentication configuration valid",
  redirect_policy_reviewed: "Same-origin redirect policy reviewed",
  application_registration_reviewed: "Application registration reviewed",
  redirect_uri_registration_proven: "Redirect URI registration proven",
  delegated_api_permission_consent_proven: "Delegated API permission consent proven",
  calling_client_association_proven: "Calling-client association proven",
  external_id_user_flow_association_proven: "External ID user-flow association proven",
  history_fallback_proven: "History fallback proven",
  supported_deployment_environment_proven: "Supported deployment environment proven",
};

interface HomeViewProps {
  readonly authentication: AuthenticationSnapshot;
  readonly activation: AuthenticationActivationReadiness;
  readonly profileSource: BackendAuthorizationProfileSourceReadiness;
}

function HomeView({ authentication, activation, profileSource }: HomeViewProps) {
  const profile = authentication.authorizationProfile;
  return (
    <>
      <section className="hero-panel" aria-labelledby="engineer4me-heading">
        <div>
          <p className="eyebrow">Controlled activation readiness</p>
          <h1 id="engineer4me-heading">Engineering decisions, with evidence visible</h1>
          <p className="hero-panel__lead">
            Engineer4Me now presents reviewed identity activation, backend profile, and protected-workspace boundaries without starting an identity-provider or backend operation.
          </p>
        </div>
        <div className="hero-panel__control" aria-label="Current release status">
          <span className="data-label">Current controlled state</span>
          <StatusBadge tone="positive">Activation source verified</StatusBadge>
          <span>Credentials, permissions, redirect execution, tokens, and protected requests remain inactive</span>
        </div>
      </section>

      <section className="workspace-section" aria-labelledby="status-heading">
        <SectionHeading
          eyebrow="Readiness"
          headingId="status-heading"
          title="Product and access state remain explicit"
          description="Client-side access presentation is not a security boundary. Backend authorization remains authoritative."
        />
        <StatusSummary authenticationStatus={authentication.safeMessage} productStatus={INITIAL_PRODUCT_STATUS} />
      </section>

      <div className="workspace-grid workspace-grid--access">
        <AuthenticationSummary
          phaseLabel={authenticationPhaseLabel(authentication.phase)}
          configurationLabel={authentication.configurationReady ? "Ready" : "Blocked"}
          identityLabel={authentication.principal ? "Established" : "Not established"}
          authorizationLabel={profile ? `Backend profile ${profile.revision}` : "Not loaded"}
          organisationLabel={authentication.activeOrganisation?.organisationName ?? "Not selected"}
          roleCount={profile?.roles.length ?? 0}
          entitlementCount={profile?.entitlements.length ?? 0}
          tokenAttachmentLabel="Inactive"
        />
        <AuthenticationActivationPanel
          sourceReady={activation.sourceReady}
          interactiveExecutionReady={activation.interactiveExecutionReady}
          missingGateLabels={activation.missingGates.map((gate) => GATE_LABELS[gate] ?? gate)}
          safeSummary={activation.safeSummary}
        />
        <OrganisationProfilePanel
          sourceState={profileSource.state}
          sourceReason={profileSource.state === "ready" ? profileSource.operation.key : "No accepted backend authorization-profile operation"}
          profileLabel={profile ? `Backend profile ${profile.revision}` : "Not loaded"}
          organisationLabel={authentication.activeOrganisation?.organisationName ?? "Not selected"}
        />
        <AccessAuditPanel records={[]} />
      </div>

      <section className="workspace-section" aria-labelledby="capability-heading">
        <SectionHeading
          eyebrow="Capability map"
          headingId="capability-heading"
          title="Controlled routes, no implied integration"
          description="Each destination has an owner and access boundary. A navigable route does not imply identity, entitlement, API, or engineering capability availability."
        />
        <div className="capability-grid">
          {PROTECTED_ROUTES.filter((route) => route.id !== "security").map((route) => (
            <article className="capability-card" id={`capability-${route.id}`} key={route.id}>
              <div className="capability-card__heading"><h3>{route.label}</h3><StatusBadge tone="warning">Protected</StatusBadge></div>
              <p>Owned by {route.owner.replaceAll("_", " ")}.</p>
              <Link className="capability-card__link" to={route.path}>Open controlled route</Link>
              <span className="capability-card__boundary">No protected backend content</span>
            </article>
          ))}
        </div>
      </section>

      <div className="workspace-grid">
        <EvidencePanel model={SHELL_EVIDENCE} />
        <BoundaryNotice boundaries={PHASE_9_PRODUCT_BOUNDARIES.filter((boundary) => VISIBLE_BOUNDARY_IDS.has(boundary.id))} />
      </div>
    </>
  );
}

function NotFoundView() {
  const location = useLocation();
  const model = createStateExperience("not_found", {
    detail: `The address ${location.pathname.slice(0, 160)} does not match a controlled Engineer4Me route.`,
  });
  return <StateExperience action={<Link className="e4m-link-button" to="/">Return to workspace</Link>} model={model} />;
}

function App() {
  const readiness = readAuthenticationConfiguration();
  const authentication = createInitialAuthenticationSnapshot(readiness);
  const accessContext = createRouteAccessContext(authentication);
  const redirectPolicy = createAuthenticationRedirectPolicy({
    applicationOrigin: window.location.origin,
    allowedReturnPaths: APP_ROUTES.map((route) => route.path),
  });
  const activation = evaluateAuthenticationActivationReadiness({
    configuration: readiness,
    redirectPolicy,
    evidence: NO_AUTHENTICATION_ACTIVATION_EVIDENCE,
  });
  const profileSource = evaluateBackendAuthorizationProfileSource();
  const profile = authentication.authorizationProfile;

  return (
    <AppShell
      accessProfileLabel={profile ? `Backend profile ${profile.revision}` : "Not loaded"}
      authenticationLabel={authenticationPhaseLabel(authentication.phase)}
      connectivityLabel="unknown"
      organisationLabel={authentication.activeOrganisation?.organisationName ?? "Not selected"}
      projectLabel="No project selected"
    >
      <Routes>
        <Route path={HOME_ROUTE.path} element={<HomeView activation={activation} authentication={authentication} profileSource={profileSource} />} />
        {PROTECTED_ROUTES.map((route) => (
          <Route
            element={<ProtectedWorkspace
              accessContext={accessContext}
              apiTransportActive={false}
              authentication={authentication}
              profileSource={profileSource}
              route={route}
            />}
            key={route.id}
            path={route.path}
          />
        ))}
        <Route path="*" element={<NotFoundView />} />
      </Routes>
    </AppShell>
  );
}

export default App;
