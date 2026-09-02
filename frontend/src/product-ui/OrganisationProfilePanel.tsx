import { StatusBadge } from "../design-system";

export interface OrganisationProfilePanelProps {
  readonly sourceState: "unavailable" | "ready";
  readonly sourceReason: string;
  readonly profileLabel: string;
  readonly organisationLabel: string;
}

export function OrganisationProfilePanel({
  sourceState,
  sourceReason,
  profileLabel,
  organisationLabel,
}: OrganisationProfilePanelProps) {
  return (
    <section className="profile-panel" aria-labelledby="organisation-profile-heading">
      <div className="profile-panel__heading">
        <div>
          <p className="eyebrow">Backend authority</p>
          <h2 id="organisation-profile-heading">Organisation and access profile transport</h2>
        </div>
        <StatusBadge tone={sourceState === "ready" ? "information" : "warning"}>
          {sourceState === "ready" ? "Source ready" : "Unavailable"}
        </StatusBadge>
      </div>
      <dl className="profile-panel__summary">
        <div><dt>Accepted profile operation</dt><dd>{sourceReason}</dd></div>
        <div><dt>Authorization profile</dt><dd>{profileLabel}</dd></div>
        <div><dt>Organisation</dt><dd>{organisationLabel}</dd></div>
      </dl>
      <p className="profile-panel__boundary">
        No profile endpoint is inferred from route names. Backend identity, role, entitlement, organisation, and resource authorization remain authoritative.
      </p>
    </section>
  );
}
