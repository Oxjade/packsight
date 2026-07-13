import { describe, expect, it } from "vitest";
import type { SecurityFinding } from "@packsight/report-schema";
import { calculateSecurityHygieneScore, gradeFor } from "./index.js";

describe("score model", () => {
  it("deducts by severity and confidence with category caps", () => {
    const findings: SecurityFinding[] = [
      finding("SUI-VERSION-002", "high", "medium"),
      finding("SUI-VERSION-003", "medium", "medium"),
      finding("SUI-DEPS-001", "low", "confirmed")
    ];

    expect(calculateSecurityHygieneScore(findings)).toBe(89);
  });

  it("assigns grades", () => {
    expect(gradeFor(92)).toBe("A");
    expect(gradeFor(84)).toBe("B");
    expect(gradeFor(72)).toBe("C");
    expect(gradeFor(55)).toBe("D");
    expect(gradeFor(40)).toBe("F");
  });
});

function finding(
  ruleId: string,
  severity: SecurityFinding["severity"],
  confidence: SecurityFinding["confidence"]
): SecurityFinding {
  return {
    ruleId,
    title: ruleId,
    description: ruleId,
    severity,
    confidence,
    status: "open",
    evidence: [{ type: "static_analysis", value: ruleId }],
    affectedComponents: [ruleId],
    impact: "test",
    recommendation: "test"
  };
}
