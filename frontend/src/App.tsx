import { readAuthenticationConfiguration } from "./auth/config";
import {
  INITIAL_PRODUCT_STATUS,
  PHASE_9_PRODUCT_BOUNDARIES,
  type EngineeringEvidenceViewModel,
} from "./foundation";
import { SectionHeading, StatusBadge } from "./design-system";
import { BoundaryNotice, EvidencePanel, StatusSummary } from "./product-ui";
import { AppShell } from "./shell";

const SHELL_EVIDENCE: EngineeringEvidenceViewModel = {
  evidence: [],
  confidence: {
    level: "unknown",
    basis: ["No connected engineering result is displayed by this shell."],
  },
  assumptions: [],
  limitations: [
    "API transport and engineering capability integration remain inactive.",
  ],
  warnings: [
    "Do not treat the product shell as engineering approval or operational authorization.",
  ],
  revision: {
    revision: "Phase 9 shell foundation",
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

function App() {
  const authentication = readAuthenticationConfiguration();
  const authenticationDetail = authentication.ready
    ? "Public configuration is present; sign-in remains blocked pending later security gates."
    : `Public configuration is incomplete: ${authentication.missing.join(", ")}.`;

  return (
    <AppShell authenticationLabel="Blocked" connectivityLabel="unknown">
      <section className="hero-panel" aria-labelledby="engineer4me-heading">
        <div>
          <p className="eyebrow">Mobile-first product foundation</p>
          <h1 id="engineer4me-heading">Engineering decisions, with evidence visible</h1>
          <p className="hero-panel__lead">
            Engineer4Me is being assembled as a controlled multidisciplinary workspace.
            This shell presents status and product boundaries without activating
            authentication, API transport, browser routing, or engineering workflows.
          </p>
        </div>
        <div className="hero-panel__control" aria-label="Current release status">
          <span className="data-label">Current controlled state</span>
          <StatusBadge tone="positive">Frontend foundation verified</StatusBadge>
          <span>Phase 9 design-system and shell review</span>
        </div>
      </section>

      <section className="workspace-section" aria-labelledby="status-heading">
        <SectionHeading
          eyebrow="Readiness"
          headingId="status-heading"
          title="Product status is explicit"
          description="Inactive and unavailable functions remain visibly fail closed."
        />
        <StatusSummary
          authenticationStatus={authenticationDetail}
          productStatus={INITIAL_PRODUCT_STATUS}
        />
      </section>

      <section className="workspace-section" aria-labelledby="capability-heading">
        <SectionHeading
          eyebrow="Capability map"
          headingId="capability-heading"
          title="One workspace, controlled capability handoffs"
          description="Capability cards are information architecture only; no backend integration or browser routes are active."
        />
        <div className="capability-grid">
          {[
            ["selection", "Selection & sizing", "Evidence-led equipment and application workflows."],
            ["troubleshooting", "Troubleshooting", "Symptoms, hypotheses, verification, and permanent corrective action."],
            ["knowledge", "Knowledge & evidence", "Approved organisational engineering knowledge and traceability."],
            ["documents", "Documents", "Controlled ingestion, processing, review, and document lineage."],
            ["calculations", "Calculations", "Transparent assumptions, coefficients, units, and limitations."],
            ["projects", "Projects", "Future multidisciplinary workspace and change-impact coordination."],
          ].map(([id, title, detail]) => (
            <article className="capability-card" id={`capability-${id}`} key={id}>
              <div className="capability-card__heading">
                <h3>{title}</h3>
                <StatusBadge>Planned</StatusBadge>
              </div>
              <p>{detail}</p>
              <span className="capability-card__boundary">No route or API connection</span>
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
    </AppShell>
  );
}

export default App;
