import { render, screen, within } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { LocalTranscriptionAssessmentPanel } from "./LocalTranscriptionAssessmentPanel";
describe("local-first assessment boundary",()=>{
 it("presents the selected direction without activation controls",()=>{
  render(<LocalTranscriptionAssessmentPanel />);
  const region=screen.getByRole("region",{name:"Local-first transcription assessment"});
  expect(region).toHaveAttribute("aria-labelledby","local-transcription-assessment-heading");
  expect(within(region).getByRole("heading",{level:2,name:"Local-first transcription assessment"})).toBeInTheDocument();
  expect(within(region).getByText(/Local-only assessment is selected/)).toBeInTheDocument();
  expect(within(region).getByText(/not measured speech accuracy/)).toBeInTheDocument();
  expect(within(region).queryByRole("button")).not.toBeInTheDocument();
  expect(within(region).queryByRole("textbox")).not.toBeInTheDocument();
 });
});
