import { StatusBadge, type StatusTone } from "../design-system";

export interface AuthenticationSummaryProps {
  readonly phaseLabel: string;
  readonly configurationLabel: string;
  readonly identityLabel: string;
  readonly authorizationLabel: string;
  readonly organisationLabel: string;
  readonly roleCount: number;
  readonly entitlementCount: number;
  readonly tokenAttachmentLabel: string;
}

function countLabel(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

export function AuthenticationSummary({
  phaseLabel,
  configurationLabel,
  identityLabel,
  authorizationLabel,
  organisationLabel,
  roleCount,
  entitlementCount,
  tokenAttachmentLabel,
}: AuthenticationSummaryProps) {
  const phaseTone: StatusTone = phaseLabel === "Authenticated" ? "positive" : "warning";
  const items = [
    ["Configuration", configurationLabel],
    ["Identity", identityLabel],
    ["Authorization profile", authorizationLabel],
    ["Organisation", organisationLabel],
    ["Roles", countLabel(roleCount, "role")],
    ["Entitlements", countLabel(entitlementCount, "entitlement")],
    ["Bearer attachment", tokenAttachmentLabel],
  ] as const;

  return (
    <section className="access-summary" aria-labelledby="authentication-summary-heading">
      <div className="access-summary__heading">
        <div>
          <p className="eyebrow">Access control</p>
          <h2 id="authentication-summary-heading">Authentication and access status</h2>
        </div>
        <StatusBadge tone={phaseTone}>{phaseLabel}</StatusBadge>
      </div>
      <dl className="access-summary__grid">
        {items.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <p className="access-summary__boundary">
        Identity-provider execution, bearer attachment, and protected backend requests remain inactive.
        Backend authorization remains authoritative.
      </p>
    </section>
  );
}
