import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { scanSuiPackage } from "./index.js";

const rootFixturePath = resolve(process.cwd(), "fixtures/sui/legacy-package");
const packageFixturePath = resolve(process.cwd(), "../../../fixtures/sui/legacy-package");
const fixturePath = existsSync(rootFixturePath) ? rootFixturePath : packageFixturePath;

describe("Sui adapter", () => {
  it("detects sensitive deprecated legacy entry functions without version gates", async () => {
    const result = await scanSuiPackage({
      network: "local",
      customGraphqlUrl: "local",
      packageId: "0xabc",
      sourcePath: fixturePath
    });

    expect(result.callableSurface.length).toBeGreaterThan(0);
    expect(result.findings.map((finding) => finding.ruleId)).toContain("SUI-VERSION-002");
  });

  it("validates Sui package IDs", async () => {
    await expect(
      scanSuiPackage({
        network: "local",
        customGraphqlUrl: "local",
        packageId: "not-a-package"
      })
    ).rejects.toThrow(/Invalid Sui package ID/);
  });
});
