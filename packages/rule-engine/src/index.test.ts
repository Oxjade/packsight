import { describe, expect, it } from "vitest";
import { scoreFindings } from "./index.js";
import type { SecurityFinding } from "@packsight/report-schema";

const baseFinding: SecurityFinding = {
  ruleId: "SUI-VERSION-002",
  title: "Sensitive legacy entry function lacks an observable version gate",
  description: "Test finding",
  severity: "high",
  confidence: "medium",
  status: "open",
  chainFamily: "sui",
  evidence: [{ type: "source_function", value: "rewards::claim_legacy" }],
  affectedComponents: ["rewards::claim_legacy"],
  impact: "Manual review required.",
  recommendation: "Add a version gate."
};

describe("scoreFindings", () => {
  it("calculates a capped security hygiene score", () => {
    const result = scoreFindings([baseFinding]);
    expect(result.score).toBe(91);
    expect(result.grade).toBe("A");
  });
});
