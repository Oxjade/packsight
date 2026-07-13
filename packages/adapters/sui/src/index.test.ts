import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { scanSuiPackage } from "./index.js";

const rootFixturePath = resolve(process.cwd(), "fixtures/sui/legacy-package");
const packageFixturePath = resolve(process.cwd(), "../../../fixtures/sui/legacy-package");
const fixturePath = existsSync(rootFixturePath) ? rootFixturePath : packageFixturePath;

describe("Sui adapter", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

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

  it("reports callable previous package versions when scanning the latest package", async () => {
    const latestPackage = "0x222";
    const legacyPackage = "0x111";
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as { variables?: { address?: string } };
      const address = body.variables?.address;
      const payload = address === latestPackage ? latestGraphqlPayload(latestPackage, legacyPackage) : legacyGraphqlPayload(legacyPackage, latestPackage);
      return new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } });
    });

    const result = await scanSuiPackage({
      network: "mainnet",
      customGraphqlUrl: "https://example.test/graphql",
      packageId: latestPackage
    });

    expect(result.findings.map((finding) => finding.ruleId)).toContain("SUI-VERSION-007");
    expect(result.callableSurface).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          address: legacyPackage,
          name: `${legacyPackage}::oracle::update`,
          deprecated: true,
          reachable: true
        })
      ])
    );
    expect(result.runtimeChecks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          packageAddress: legacyPackage,
          functionName: "oracle::update",
          runtimeStatus: "simulation_required"
        })
      ])
    );
    expect(result.versionFunctionDiffs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          packageAddress: legacyPackage,
          comparedToAddress: latestPackage,
          status: "present_in_upgrade"
        })
      ])
    );
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

function latestGraphqlPayload(latestPackage: string, legacyPackage: string) {
  return packagePayload({
    packageId: latestPackage,
    version: 2,
    previousVersions: [{ address: legacyPackage, version: 1, digest: "legacy-digest" }],
    laterVersions: []
  });
}

function legacyGraphqlPayload(legacyPackage: string, latestPackage: string) {
  return packagePayload({
    packageId: legacyPackage,
    version: 1,
    previousVersions: [],
    laterVersions: [{ address: latestPackage, version: 2, digest: "latest-digest" }]
  });
}

function packagePayload(input: {
  packageId: string;
  version: number;
  previousVersions: Array<{ address: string; version: number; digest: string }>;
  laterVersions: Array<{ address: string; version: number; digest: string }>;
}) {
  return {
    data: {
      object: {
        address: input.packageId,
        version: input.version,
        digest: `${input.packageId}-digest`,
        previousTransaction: { digest: `${input.packageId}-tx` },
        asMovePackage: {
          address: input.packageId,
          version: input.version,
          digest: `${input.packageId}-digest`,
          linkage: [],
          packageVersionsBefore: {
            pageInfo: { hasNextPage: false },
            nodes: input.previousVersions
          },
          packageVersionsAfter: {
            pageInfo: { hasNextPage: false },
            nodes: input.laterVersions
          },
          modules: {
            nodes: [
              {
                name: "oracle",
                functions: {
                  nodes: [
                    {
                      name: "update",
                      fullyQualifiedName: `${input.packageId}::oracle::update`,
                      isEntry: true,
                      visibility: "PUBLIC",
                      parameters: [{ repr: "&mut 0x2::object::Object" }],
                      return: []
                    }
                  ]
                }
              }
            ]
          }
        }
      },
      checkpoint: { sequenceNumber: "123" }
    }
  };
}
