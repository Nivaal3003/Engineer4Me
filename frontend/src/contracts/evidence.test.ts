import { createUnreviewedEvidenceEnvelope } from "./evidence";

describe("evidence envelopes", () => {
  it("keeps evidence, confidence, revision, and approval ownership explicit", () => {
    const envelope = createUnreviewedEvidenceEnvelope({
      value: { result: 42 },
      revision: "draft-1",
      approvalOwner: "Authorised organisation engineer",
      limitations: ["No conformity claim"],
    });
    expect(envelope.confidence).toBe("not_assessed");
    expect(envelope.approval).toEqual({
      status: "unreviewed",
      owner: "Authorised organisation engineer",
      approvedAt: null,
    });
    expect(envelope.limitations).toContain("No conformity claim");
  });
});
