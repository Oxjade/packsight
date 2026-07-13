# API

## Create Scan

```http
POST /v1/scans
```

```json
{
  "targetType": "chain_address",
  "chainFamily": "sui",
  "network": "mainnet",
  "address": "0x0f51...",
  "repositoryUrl": "https://github.com/example/protocol",
  "commitSha": "optional"
}
```

Supported `chainFamily` values:

- `sui`: scans a Sui package ID through GraphQL metadata and optional Move source.
- `solana`: scans a Solana program ID through JSON-RPC metadata and optional Anchor IDL.
- `evm`: scans an EVM contract address through JSON-RPC metadata and optional ABI.

Optional local-development fields:

```json
{
  "sourcePath": "fixtures/sui/legacy-package",
  "customGraphqlUrl": "https://graphql.mainnet.sui.io/graphql",
  "customRpcUrl": "https://ethereum.publicnode.com"
}
```

Use `Idempotency-Key` to avoid duplicate scan creation.

## Examples

### Sui

```json
{
  "targetType": "chain_address",
  "chainFamily": "sui",
  "network": "mainnet",
  "address": "0x0f51f9eb63574a1d12b62295599ac4f8231197f95b3cce9a516daba64f419d06"
}
```

### Solana

```json
{
  "targetType": "chain_address",
  "chainFamily": "solana",
  "network": "mainnet-beta",
  "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
}
```

### EVM

```json
{
  "targetType": "chain_address",
  "chainFamily": "evm",
  "network": "mainnet",
  "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
  "customRpcUrl": "https://ethereum.publicnode.com"
}
```

## Get Report

```http
GET /v1/scans/:scanId/report
```

Returns a normalized `ScanReport`.

Important fields:

- `versions`: version, slot or block-oriented deployment facts.
- `callableSurface`: functions/instructions/contracts with accessibility and reachability labels when known.
- `versionFunctionDiffs`: old-vs-latest Sui function comparison.
- `packageLinks`: Sui linkage comparison.
- `runtimeChecks`: Sui public old-function state proof checklist.
- `dependencies`: parsed dependency and linkage records.
- `findings`: rule output with severity, confidence, evidence, impact, recommendation and limitations.
- `dataCoverage`: completeness status for metadata, source, history, interface, dependency graph and runtime reachability.
