import { render, screen } from "@testing-library/react";
import {
  CAPABILITY_RESULT_CONTROLS,
  createScriptedCapabilityAdapter,
} from "../capabilities";
import { CapabilityWorkspacePreview } from "./CapabilityWorkspacePreview";

describe("capability workspace in-memory vertical slice", () => {
  it("renders a decoded scripted result without network activity", async () => {
    const scripted = createScriptedCapabilityAdapter("knowledge", [{
      kind: "result",
      value: {
        schemaVersion: 1,
        capabilityId: "knowledge",
        operationKey: "get_api_v1_knowledge_summaries",
        state: "ready",
        value: {
          title: "Verified knowledge summaries",
          summary: "One in-memory record demonstrates the knowledge vertical slice.",
          itemCount: 1,
          payload: [{ knowledgeId: "fixture-1", status: "verified" }],
        },
        evidence: [{
          sourceId: "fixture:knowledge:summary",
          title: "Verified knowledge fixture",
          revision: "1",
          locator: "unit-test",
        }],
        assumptions: ["The fixture is not an organisational knowledge record."],
        limitations: ["No live knowledge repository request was made."],
        warnings: ["Applicability must be verified before engineering use."],
        confidence: "not_assessed",
        revision: "phase9-step371-v1",
        approval: {
          status: "review_required",
          owner: "Engineer4Me product owner",
          approvedAt: null,
        },
        controls: CAPABILITY_RESULT_CONTROLS,
      },
    }]);
    const result = await scripted.adapter.execute({
      requestId: "workspace-preview-knowledge-1",
      capabilityId: "knowledge",
      operationKey: "get_api_v1_knowledge_summaries",
      input: { status: "verified" },
    });
    render(
      <CapabilityWorkspacePreview
        capabilityId="knowledge"
        result={result}
        sourceMode="in_memory_contract_only"
      />,
    );
    expect(screen.getByRole("heading", { name: "Verified knowledge summaries" })).toBeInTheDocument();
    expect(screen.getByText("Verified knowledge fixture")).toBeInTheDocument();
    expect(scripted.networkRequestsPerformed).toBe(false);
    expect(scripted.adapter.liveTransportActive).toBe(false);
  });

  it("shows an explicit result-empty boundary", () => {
    render(
      <CapabilityWorkspacePreview
        capabilityId="projects"
        result={null}
        sourceMode="in_memory_contract_only"
      />,
    );
    expect(screen.getByRole("heading", { name: "No capability result loaded" })).toBeInTheDocument();
    expect(screen.getByText(/No protected request has been sent/)).toBeInTheDocument();
  });
});
