import { describe, expect, it } from "vitest";
import { parseMoveFunctions } from "./index.js";

describe("Move parser", () => {
  it("detects deprecated sensitive entry functions without version gates", () => {
    const functions = parseMoveFunctions(
      `
module demo::rewards {
  /// deprecated legacy path
  public entry fun withdraw_legacy(vault: &mut Vault) {
    transfer::public_transfer(vault.coin, @0x1);
  }
}
`,
      "sources/rewards.move"
    );

    expect(functions[0]).toMatchObject({
      moduleName: "rewards",
      functionName: "withdraw_legacy",
      entry: true,
      deprecated: true,
      mutatesState: true,
      valueSensitive: true,
      hasVersionGate: false
    });
  });
});
