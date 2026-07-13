import { describe, expect, it } from "vitest";
import { scanSourceFiles } from "./index.js";

describe("dependency scanner", () => {
  it("reports missing Move.lock and mutable Git dependencies", () => {
    const result = scanSourceFiles({
      "Move.toml": `
        [package]
        name = "Example"

        [dependencies.Sui]
        git = "https://github.com/MystenLabs/sui.git"
        branch = "mainnet"
      `
    });

    expect(result.hasMoveManifest).toBe(true);
    expect(result.hasMoveLock).toBe(false);
    expect(result.findings.map((finding) => finding.ruleId)).toContain("SUI-DEPS-001");
    expect(result.findings.map((finding) => finding.ruleId)).toContain("SUI-DEPS-002");
  });
});
