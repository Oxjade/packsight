# packsight

packsight is a multichain audit-support scanner for legacy on-chain interfaces, package linkage, upgrade posture and missing source/interface evidence.

It is built for auditors, protocol engineers and security reviewers who need to answer careful questions:

- Is this deployed package, program or contract the latest version?
- Are old public functions still interface-accessible?
- Did linked packages or proxy implementation facts change after an upgrade?
- Do public legacy functions look capable of mutating state?
- Is there evidence of a version guard, or does this need runtime simulation?

packsight is not an exploit oracle. It separates confirmed facts from static-analysis findings, heuristics, missing information and manual-review requirements.

## Supported Targets

### Sui

Sui support is the deepest current adapter.

packsight fetches:

- package object version, digest and publish transaction;
- package versions before and after the scanned package;
- modules and function visibility;
- function parameters and return types;
- public/friend/private/entry accessibility;
- old-vs-latest function diffs;
- Sui Move package linkage;
- changed linkage between legacy and latest package versions.

For legacy packages, packsight emits a runtime/state proof checklist for every public or entry old function. The checklist includes:

- interface reachability;
- mutation hint from signature/source;
- version-guard evidence status;
- runtime simulation status;
- required evidence to prove whether the function succeeds or aborts.

### Solana

Solana support fetches program account metadata through JSON-RPC.

packsight reports:

- program owner and executable status;
- BPF upgradeable-loader ProgramData where available;
- deployment slot;
- active upgrade authority;
- Anchor IDL instruction surface when an IDL is supplied.

Solana program accounts do not expose instruction names on-chain. Without IDL or source, packsight reports interface coverage as unavailable rather than guessing.

### EVM

EVM support fetches bytecode and storage metadata through JSON-RPC.

packsight reports:

- chain ID and scan block;
- deployed bytecode presence;
- EIP-1967 implementation/admin/beacon slots;
- ABI-derived function surface when local `abi.json` or explorer ABI is available.

Without ABI or verified source, packsight records a wildcard contract surface and an explicit coverage finding.

## Runtime Proof Model

For Sui legacy packages, the important audit question is:

```text
Can public old functions still mutate live protocol state, or do version/state guards make them abort?
```

packsight answers what can be proven from available evidence:

- `public_move_call` or `transaction_entry`: interface-accessible.
- `friend_only` or `private`: not externally callable through the normal package interface.
- `state_mutation_likely`: signature/source shows mutable state objects or source mutation.
- `state_mutation_possible`: function name or value-flow types suggest state impact.
- `read_only_likely`: no mutable parameters were observed.
- `source_guard_detected`: supplied source shows a recognized version gate.
- `source_guard_missing`: supplied source was parsed and no recognized gate was found.
- `unknown_source_unavailable`: no exact source was supplied, so guard status cannot be confirmed.
- `simulation_required`: a public old function needs dry-run or transaction simulation with live objects.

The scanner does not currently execute Sui dry-runs automatically because it needs concrete live object IDs, signer context, capabilities and safe simulation policy. The report lists the evidence auditors must collect.

## Local Development

```bash
pnpm install
pnpm --filter @packsight/api build
pnpm --filter @packsight/web build
pnpm --filter @packsight/api start
pnpm --filter @packsight/web start
```

The web app runs on:

```text
http://localhost:3000
```

The API runs on:

```text
http://localhost:4000
```

Scan state is currently in memory. Restarting the API clears previous scan IDs.

## CLI

```bash
packsight scan sui <package-id> --network mainnet
packsight scan solana <program-id> --network mainnet-beta
packsight scan evm <contract-address> --network mainnet --rpc https://ethereum.publicnode.com
```

Useful options:

```text
--source <path>      local source, ABI or IDL path
--repo <url>         repository metadata
--commit <sha>       exact commit metadata
--rpc <url>          custom Solana/EVM RPC endpoint
--graphql <url>      custom Sui GraphQL endpoint
--output <path>      write JSON report
--fail-on <level>    info, low, medium, high, critical
```

## API

Create a scan:

```http
POST /v1/scans
```

```json
{
  "targetType": "chain_address",
  "chainFamily": "sui",
  "network": "mainnet",
  "address": "0x0f51f9eb63574a1d12b62295599ac4f8231197f95b3cce9a516daba64f419d06"
}
```

Fetch the report:

```http
GET /v1/scans/:scanId/report
```

Use `Idempotency-Key` on scan creation to avoid duplicate scan records.

## Report Sections

Every report includes:

- `versions`: deployment/version facts;
- `callableSurface`: functions, instructions or interface entries;
- `versionFunctionDiffs`: Sui old-vs-latest function comparison;
- `packageLinks`: Sui package linkage comparison;
- `runtimeChecks`: Sui runtime/state proof checklist for public old functions;
- `dependencies`: manifest, lockfile and linkage records;
- `findings`: evidence-led rule output;
- `dataCoverage`: what was complete, partial, unavailable or not tested;
- `scanPoint`: checkpoint, block, slot and provider metadata.

## Verification

```bash
pnpm typecheck
pnpm test
pnpm --filter @packsight/web build
```

## Production Notes

Before accepting public uploads or arbitrary source archives:

- run analyzers in isolated workers;
- do not execute scanned project code;
- reject path traversal and symlink escapes;
- enforce CPU, memory, output and wall-clock limits;
- restrict arbitrary RPC URLs or use an allowlist;
- redact provider credentials from logs;
- persist scan records in the database instead of memory;
- rate-limit public scan creation.

## Current Limitations

- Sui runtime simulation is not automatic yet; reports identify the functions and proof needed.
- Solana instruction names require IDL/source.
- EVM function names require ABI/source.
- Missing source is a coverage gap, not proof of safety or exploitability.
- Upgradeability is a governance fact until authority ownership and process are reviewed.
