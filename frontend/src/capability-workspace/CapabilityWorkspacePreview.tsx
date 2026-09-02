import type {
  CapabilityWorkspaceResult,
  ProtectedCapabilityId,
} from "../capabilities";
import { CapabilityOperationPanel } from "./CapabilityOperationPanel";
import { CapabilityResultView } from "./CapabilityResultView";

export interface CapabilityWorkspacePreviewProps {
  readonly capabilityId: ProtectedCapabilityId;
  readonly result: CapabilityWorkspaceResult | null;
  readonly sourceMode: "in_memory_contract_only";
}

export function CapabilityWorkspacePreview({
  capabilityId,
  result,
  sourceMode,
}: CapabilityWorkspacePreviewProps) {
  if (result && result.capabilityId !== capabilityId) {
    throw new Error("Capability preview result ownership differs.");
  }
  return (
    <div
      className="capability-workspace-preview"
      data-live-transport="inactive"
      data-source-mode={sourceMode}
    >
      <CapabilityOperationPanel capabilityId={capabilityId} />
      {result ? (
        <CapabilityResultView result={result} />
      ) : (
        <section className="content-panel capability-workspace-preview__empty" aria-label="Capability result status">
          <h2>No capability result loaded</h2>
          <p>Only accepted operation metadata is presented. No protected request has been sent.</p>
        </section>
      )}
    </div>
  );
}
