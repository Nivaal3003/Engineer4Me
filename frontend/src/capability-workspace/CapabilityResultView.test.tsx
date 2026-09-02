import { render, screen } from "@testing-library/react";
import {
  CAPABILITY_RESULT_CONTROLS,
  decodeCapabilityWorkspaceResult,
} from "../capabilities";
import { CapabilityResultView } from "./CapabilityResultView";

const RESULT = decodeCapabilityWorkspaceResult({
  schemaVersion: 1,
  capabilityId: "selection",
  operationKey: "get_api_v1_manufacturers",
  state: "ready",
  value: {
    title: "Manufacturer catalogue evidence",
    summary: "One test-only record demonstrates the evidence presentation contract.",
    itemCount: 1,
    payload: [{ manufacturerId: "fixture-1", name: "Example" }],
  },
  evidence: [{
    sourceId: "fixture:selection:manufacturers",
    title: "Manufacturer catalogue fixture",
    revision: "1",
    locator: "unit-test",
  }],
  assumptions: ["The fixture is not a live backend response."],
  limitations: ["No product suitability calculation was performed."],
  warnings: ["The user must approve the final product decision."],
  confidence: "not_assessed",
  revision: "phase9-step370-v1",
  approval: {
    status: "unreviewed",
    owner: "Engineer4Me product owner",
    approvedAt: null,
  },
  controls: CAPABILITY_RESULT_CONTROLS,
}, {
  capabilityId: "selection",
  operationKey: "get_api_v1_manufacturers",
});

it("renders an evidence-led in-memory result without implying live integration", () => {
  render(<CapabilityResultView result={RESULT} />);
  expect(screen.getByRole("heading", { name: "Manufacturer catalogue evidence" })).toBeInTheDocument();
  expect(screen.getByText("Manufacturer catalogue fixture")).toBeInTheDocument();
  expect(screen.getByText("No product suitability calculation was performed.")).toBeInTheDocument();
  expect(screen.getByText("Vendor neutrality required")).toBeInTheDocument();
  expect(screen.getByText("No standards conformity claim")).toBeInTheDocument();
  expect(screen.getByText(/Live transport remains inactive/)).toBeInTheDocument();
});
