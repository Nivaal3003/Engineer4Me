import type { ProtectedCapabilityId } from "../capabilities";
import { createCapabilityOperationCatalogue } from "./operations";

export type CapabilityVerticalSliceAvailability =
  | "evidence_led_in_memory_ready"
  | "no_accepted_backend_operation";

export interface CapabilityVerticalSliceDefinition {
  readonly capabilityId: ProtectedCapabilityId;
  readonly label: string;
  readonly purpose: string;
  readonly availability: CapabilityVerticalSliceAvailability;
  readonly representativeQueryOperationKey: string | null;
  readonly liveTransportActive: false;
  readonly protectedContentAvailable: false;
  readonly automaticBestBrandSelection: false;
  readonly standardsConformityClaimed: false;
}

const DEFINITIONS = Object.freeze([
  {
    capabilityId: "selection",
    label: "Selection & sizing",
    purpose: "Present evidence-led catalogue and selection-result contracts without ranking a best brand.",
    representativeQueryOperationKey: "get_api_v1_manufacturers",
  },
  {
    capabilityId: "troubleshooting",
    label: "Troubleshooting",
    purpose: "Remain explicitly unavailable until an accepted troubleshooting operation exists.",
    representativeQueryOperationKey: null,
  },
  {
    capabilityId: "knowledge",
    label: "Knowledge & evidence",
    purpose: "Present traceable knowledge summaries with revision, confidence, and approval ownership.",
    representativeQueryOperationKey: "get_api_v1_knowledge_summaries",
  },
  {
    capabilityId: "ingestion",
    label: "Documents",
    purpose: "Present bounded ingestion statistics and job evidence without uploading or processing a file.",
    representativeQueryOperationKey: "get_api_v1_ingestion_statistics",
  },
  {
    capabilityId: "calculations",
    label: "Calculations",
    purpose: "Present calculation catalogues and result evidence without making a standards conformity claim.",
    representativeQueryOperationKey: "getAnalyzerTechnologyCatalogue",
  },
  {
    capabilityId: "designs",
    label: "Design cases",
    purpose: "Present controlled design-case summaries without changing or approving a design.",
    representativeQueryOperationKey: "listDesignCases",
  },
  {
    capabilityId: "projects",
    label: "Projects",
    purpose: "Remain explicitly unavailable until an accepted multidisciplinary project operation exists.",
    representativeQueryOperationKey: null,
  },
  {
    capabilityId: "security",
    label: "Access & audit",
    purpose: "Remain explicitly unavailable until accepted backend access-profile and audit operations exist.",
    representativeQueryOperationKey: null,
  },
] as const satisfies readonly Omit<
  CapabilityVerticalSliceDefinition,
  | "availability"
  | "liveTransportActive"
  | "protectedContentAvailable"
  | "automaticBestBrandSelection"
  | "standardsConformityClaimed"
>[]);

export const CAPABILITY_VERTICAL_SLICES: readonly CapabilityVerticalSliceDefinition[] =
  Object.freeze(DEFINITIONS.map((definition) => {
    const catalogue = createCapabilityOperationCatalogue(definition.capabilityId);
    const expectedAvailability: CapabilityVerticalSliceAvailability =
      catalogue.totalOperationCount > 0
        ? "evidence_led_in_memory_ready"
        : "no_accepted_backend_operation";
    if (
      (definition.representativeQueryOperationKey === null) !==
      (expectedAvailability === "no_accepted_backend_operation")
    ) {
      throw new Error(`Vertical slice availability differs for ${definition.capabilityId}.`);
    }
    if (
      definition.representativeQueryOperationKey !== null &&
      !catalogue.representativeQuery
    ) {
      throw new Error(`Vertical slice query operation is unavailable for ${definition.capabilityId}.`);
    }
    return Object.freeze({
      ...definition,
      availability: expectedAvailability,
      liveTransportActive: false as const,
      protectedContentAvailable: false as const,
      automaticBestBrandSelection: false as const,
      standardsConformityClaimed: false as const,
    });
  }));

const BY_ID: ReadonlyMap<ProtectedCapabilityId, CapabilityVerticalSliceDefinition> =
  new Map(CAPABILITY_VERTICAL_SLICES.map((item) => [item.capabilityId, item] as const));

export function getCapabilityVerticalSlice(
  capabilityId: ProtectedCapabilityId,
): CapabilityVerticalSliceDefinition {
  const definition = BY_ID.get(capabilityId);
  if (!definition) {
    throw new Error(`Unknown capability vertical slice: ${capabilityId}`);
  }
  return definition;
}
