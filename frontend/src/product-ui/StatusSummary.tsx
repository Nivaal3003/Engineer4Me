import type { ProductStatusViewModel } from "../foundation";
import { StatusBadge } from "../design-system";

export interface ProductStatusItem {
  readonly label: string;
  readonly value: string;
  readonly detail: string;
  readonly tone: "neutral" | "information" | "positive" | "warning" | "critical";
}

export interface StatusSummaryProps {
  readonly productStatus: ProductStatusViewModel;
  readonly authenticationStatus: string;
}

export function StatusSummary({
  productStatus,
  authenticationStatus,
}: StatusSummaryProps) {
  const items: readonly ProductStatusItem[] = [
    {
      label: "Product shell",
      value: "Ready for controlled review",
      detail: "Responsive and accessible source foundation only.",
      tone: "positive",
    },
    {
      label: "Authentication activation",
      value: "Blocked",
      detail: authenticationStatus,
      tone: "warning",
    },
    {
      label: "API transport",
      value: "Inactive",
      detail: "No backend request or bearer-token attachment is enabled.",
      tone: "neutral",
    },
    {
      label: "Connectivity",
      value: productStatus.connectivity,
      detail: productStatus.detail ?? "No controlled transport is connected.",
      tone: productStatus.connectivity === "degraded" ? "warning" : "information",
    },
  ];

  return (
    <dl className="status-summary" aria-label="Engineer4Me product status">
      {items.map((item) => (
        <div className="status-summary__item" key={item.label}>
          <dt>{item.label}</dt>
          <dd>
            <StatusBadge tone={item.tone}>{item.value}</StatusBadge>
            <span>{item.detail}</span>
          </dd>
        </div>
      ))}
    </dl>
  );
}
