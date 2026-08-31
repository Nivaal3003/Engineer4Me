/**
 * Information-architecture ownership without browser-route activation.
 * Concrete URL paths and protected-route behavior remain allocated to the
 * controlled routing milestone.
 */
export type CapabilityAreaId =
  | "home"
  | "selection"
  | "troubleshooting"
  | "knowledge"
  | "ingestion"
  | "calculations"
  | "designs"
  | "projects"
  | "security";

export type CapabilityAvailability =
  | "foundation_only"
  | "planned_vertical_slice"
  | "controlled_administration";

export interface CapabilityAreaDefinition {
  readonly id: CapabilityAreaId;
  readonly label: string;
  readonly owner: string;
  readonly availability: CapabilityAvailability;
  readonly browserRouteActivation: "not_authorized_in_foundation";
}

export const CAPABILITY_AREAS = Object.freeze(
  [
    ["home", "Home", "product_experience", "foundation_only"],
    ["selection", "Selection & sizing", "engineering_selection", "planned_vertical_slice"],
    ["troubleshooting", "Troubleshooting", "fault_intelligence", "planned_vertical_slice"],
    ["knowledge", "Knowledge & evidence", "engineering_knowledge", "planned_vertical_slice"],
    ["ingestion", "Documents", "document_ingestion", "planned_vertical_slice"],
    ["calculations", "Calculations", "engineering_calculations", "planned_vertical_slice"],
    ["designs", "Design cases", "engineering_design", "planned_vertical_slice"],
    ["projects", "Projects", "multidisciplinary_workspace", "planned_vertical_slice"],
    ["security", "Access & audit", "security_governance", "controlled_administration"],
  ].map(
    ([id, label, owner, availability]) =>
      ({
        id,
        label,
        owner,
        availability,
        browserRouteActivation: "not_authorized_in_foundation",
      }) as CapabilityAreaDefinition,
  ),
);
