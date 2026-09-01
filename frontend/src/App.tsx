import { Link, Route, Routes, useLocation } from "react-router";
import { readAuthenticationConfiguration } from "./auth/config";
import {
  INITIAL_PRODUCT_STATUS,
  PHASE_9_PRODUCT_BOUNDARIES,
  type EngineeringEvidenceViewModel,
} from "./foundation";
import { SectionHeading, StatusBadge } from "./design-system";
import { BoundaryNotice, EvidencePanel, StatusSummary } from "./product-ui";
import {
  APP_ROUTES,
  evaluateRouteAccess,
  INACTIVE_ROUTE_ACCESS_CONTEXT,
  routeById,
  type AppRouteDefinition,
} from "./routing";
import { AppShell } from "./shell";
import { createStateExperience, StateExperience } from "./state-experience";

const SHELL_EVIDENCE: EngineeringEvidenceViewModel = {
  evidence: [],
  confidence: {
    level: "unknown",
    basis: ["No connected engineering result is displayed by this browser shell."],
  },
  assumptions: [],
  limitations: [
    "API transport and engineering capability integration remain inactive.",
  ],
  warnings: [
    "Do not treat a route, state surface, or product shell as engineering approval or operational authorization.",
  ],
  revision: {
    revision: "Phase 9 controlled routing foundation",
    status: "draft",
    owner: "Engineer4Me product owner",
  },
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


function HomeView() {
  return (
    <>
      <section className="hero-panel" aria-labelledby="engineer4me-heading">
        <div>
          <p className="eyebrow">Controlled browser navigation</p>
          <h1 id="engineer4me-heading">Engineering decisions, with evidence visible</h1>
          <p className="hero-panel__lead">
            Engineer4Me now has same-origin browser routes and explicit protected-route ownership.
            Authentication, API transport, engineering workflows, and background caching remain fail closed.
          </p>
        </div>
        <div className="hero-panel__control" aria-label="Current release status">
          <span className="data-label">Current controlled state</span>
          <StatusBadge tone="positive">Browser routing verified</StatusBadge>
          <span>Routes expose only approved shell and state experiences</span>
        </div>
      </section>

      <section className="workspace-section" aria-labelledby="status-heading">
        <SectionHeading
          eyebrow="Readiness"
          headingId="status-heading"
          title="Product state remains explicit"
          description="Protected content, backend requests, and retries remain unavailable until their later gates pass."
        />
        <StatusSummary
          authenticationStatus="Authentication is not active; protected routes remain blocked."
          productStatus={INITIAL_PRODUCT_STATUS}
        />
      </section>

      <section className="workspace-section" aria-labelledby="capability-heading">
        <SectionHeading
          eyebrow="Capability map"
          headingId="capability-heading"
          title="Controlled routes, no implied integration"
          description="Each destination has an owner and access boundary. A navigable route does not imply API, entitlement, or engineering capability availability."
        />
        <div className="capability-grid">
          {PROTECTED_ROUTES.filter((route) => route.id !== "security").map((route) => (
            <article className="capability-card" id={`capability-${route.id}`} key={route.id}>
              <div className="capability-card__heading">
                <h3>{route.label}</h3>
                <StatusBadge tone="warning">Protected</StatusBadge>
              </div>
              <p>Owned by {route.owner.replaceAll("_", " ")}.</p>
              <Link className="capability-card__link" to={route.path}>
                Open controlled route
              </Link>
              <span className="capability-card__boundary">No API connection or protected content</span>
            </article>
          ))}
        </div>
      </section>

      <div className="workspace-grid">
        <EvidencePanel model={SHELL_EVIDENCE} />
        <BoundaryNotice
          boundaries={PHASE_9_PRODUCT_BOUNDARIES.filter((boundary) =>
            VISIBLE_BOUNDARY_IDS.has(boundary.id),
          )}
        />
      </div>
    </>
  );
}

function ProtectedCapabilityView({ route }: { readonly route: AppRouteDefinition }) {
  const access = evaluateRouteAccess(route, INACTIVE_ROUTE_ACCESS_CONTEXT);
  const entitlementDetail = access.requiredEntitlement
    ? ` Required entitlement: ${access.requiredEntitlement}.`
    : "";
  const model = createStateExperience("unavailable", {
    eyebrow: "Protected route",
    title: `${route.label} is not available`,
    detail: `${access.reason}${entitlementDetail}`,
    guidance: [
      "Browser navigation is active, but authentication and API transport are not.",
      "No engineering result, organisational record, or protected data has been disclosed.",
      "Frontend route ownership is presentation control only; backend authorization remains authoritative.",
      "Final engineering approval and operational authorization remain user or authorized-organisation responsibilities.",
    ],
  });

  return (
    <StateExperience
      action={<Link className="e4m-link-button" to="/">Return to workspace</Link>}
      model={model}
    />
  );
}

function NotFoundView() {
  const location = useLocation();
  const model = createStateExperience("not_found", {
    detail: `The address ${location.pathname.slice(0, 160)} does not match a controlled Engineer4Me route.`,
  });
  return (
    <StateExperience
      action={<Link className="e4m-link-button" to="/">Return to workspace</Link>}
      model={model}
    />
  );
}

function App() {
  const authentication = readAuthenticationConfiguration();
  const authenticationLabel = authentication.ready ? "Configured, inactive" : "Blocked";

  return (
    <AppShell authenticationLabel={authenticationLabel} connectivityLabel="unknown">
      <Routes>
        <Route path={HOME_ROUTE.path} element={<HomeView />} />
        {PROTECTED_ROUTES.map((route) => (
          <Route
            element={<ProtectedCapabilityView route={route} />}
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
