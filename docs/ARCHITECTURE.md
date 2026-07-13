# Packsight Architecture

Packsight is a TypeScript-first monorepo for scanning deployed Web3 code, source repositories, interfaces and dependency manifests. The current product supports Sui, Solana and EVM targets through one normalized report model while keeping chain-specific evidence and limitations explicit.

## Product Boundary

Packsight reports:

- confirmed facts from chain data, source files, interfaces, lockfiles, and advisories;
- static-analysis findings with evidence;
- heuristic findings with lower confidence;
- missing information and manual-review recommendations.

Packsight does not claim that every finding is exploitable, replace a manual smart-contract audit, simulate transactions, or label a function vulnerable from its name alone.

## Workspace

```text
apps/web                 Next.js App Router public scan and report UI
apps/api                 Fastify API for scan submission and report retrieval
apps/worker              Worker entrypoint for queue-backed scan execution
packages/report-schema   Normalized report types and Zod schemas
packages/scanner-core    Scan pipeline, score model, and orchestration
packages/rule-engine     Declarative rule metadata and Sui rule evaluation
packages/dependency-scanner
                          Manifest and lockfile parsers
packages/adapters/sui    Sui package, lineage and linkage adapter
packages/adapters/solana Solana program metadata and IDL adapter
packages/adapters/evm    EVM bytecode, proxy and ABI adapter
analyzers/move-analyzer  Move source parser and version-gate heuristics
fixtures/sui             Deterministic Sui fixtures
```

## Chain Data Interfaces

### Sui

The Sui adapter uses GraphQL RPC endpoints by default:

- `https://graphql.mainnet.sui.io/graphql`
- `https://graphql.testnet.sui.io/graphql`
- `https://graphql.devnet.sui.io/graphql`

Sui JSON-RPC is treated as deprecated migration surface and is not used for the default vertical slice. If a provider returns incomplete GraphQL data, the report records partial coverage instead of treating missing data as safe.

The adapter fetches:

- package object version, digest and previous transaction;
- Move package version history before and after the scanned package;
- module names and function visibility;
- Sui `linkage` entries;
- latest-package function and linkage comparison when a later package exists.

### Solana

The Solana adapter uses JSON-RPC by default:

- `https://api.mainnet-beta.solana.com`
- `https://api.testnet.solana.com`
- `https://api.devnet.solana.com`

The adapter fetches program account metadata and, for BPF upgradeable-loader programs, parses ProgramData to expose deployment slot and upgrade authority. Solana program accounts do not expose instruction names, so instruction-level coverage requires an Anchor IDL under `target/idl` or `idl`.

### EVM

The EVM adapter uses JSON-RPC. Mainnet defaults to `https://cloudflare-eth.com`; production use should configure a reliable provider through `customRpcUrl` or environment variables.

The adapter fetches:

- chain ID and scan block;
- deployed bytecode;
- EIP-1967 implementation, admin and beacon storage slots;
- ABI from local `abi.json` or explorer metadata when configured.

Without ABI or verified source, EVM callable surface is intentionally reported as a wildcard contract interface.

## Pipeline

Every scan follows the normalized pipeline:

```text
Validate input
Resolve chain and network
Fetch on-chain metadata
Resolve source and interface information
Identify current and historical versions
Build dependency graph
Build callable-surface model
Run chain-specific rules
Run dependency rules
Assign severity and confidence
Generate normalized JSON report
Render human-readable report
```

## Chain Adapters

### Sui

- network and package ID;
- optional public repository URL metadata;
- optional local source path for `Move.toml`, `Move.lock`, `Published.toml`, and `sources/**/*.move`.

It performs:

- package ID validation;
- Sui GraphQL package metadata fetch where available;
- Move source parsing for public and entry functions;
- deprecation marker detection in comments/attributes;
- shared-object/version-gate heuristics;
- Move manifest and lockfile dependency parsing;
- mutable Git dependency detection;
- missing lockfile detection;
- old package ID reference detection;
- old-vs-latest function comparison;
- package linkage diffing;
- normalized report generation with score, findings, evidence, coverage, and limitations.

### Solana

Solana scans accept:

- network and program ID;
- optional local source path containing Anchor IDL artifacts;
- optional custom RPC URL.

They perform:

- base58 program ID validation;
- program account lookup;
- executable owner and account metadata capture;
- BPF upgradeable-loader ProgramData parsing;
- active upgrade authority finding;
- Anchor IDL instruction extraction when supplied;
- explicit interface coverage finding when IDL/source is unavailable.

### EVM

EVM scans accept:

- network and contract address;
- optional local source path containing `abi.json`;
- optional custom RPC URL.

They perform:

- 20-byte address validation;
- bytecode, chain ID and block lookup;
- EIP-1967 proxy slot checks;
- local or explorer ABI function extraction;
- explicit source/interface coverage finding when ABI is unavailable.

## Security Model

Uploaded repositories and archives are hostile. The API server must not execute uploaded code. Production workers should run analyzers in disposable containers with:

- no host Docker socket;
- read-only root filesystem where possible;
- no privileged mode;
- CPU, memory, process, and wall-clock limits;
- blocked internal network ranges;
- bounded archive extraction and symlink escape checks;
- no package install scripts.

The MVP code keeps parser-based scanning separate from process execution so the production worker can wrap analyzers in isolated containers without changing report semantics.

## Storage Model

The repository includes the normalized domain model first. Database migrations are the next persistence step and should include immutable raw artifacts, normalized findings, dependency records, scan events, and export rows. Raw artifacts must be addressed by SHA-256 hash.

## API Shape

The API exposes:

```text
POST   /v1/scans
GET    /v1/scans/:scanId
GET    /v1/scans/:scanId/status
GET    /v1/scans/:scanId/report
GET    /v1/scans/:scanId/findings
GET    /v1/scans/:scanId/dependencies
GET    /v1/scans/:scanId/versions
POST   /v1/scans/:scanId/rescan
POST   /v1/scans/:scanId/export
GET    /v1/rules
GET    /v1/rules/:ruleId
GET    /health
GET    /ready
```

The initial implementation stores jobs in memory for local development. Redis/BullMQ and PostgreSQL are represented in Docker Compose and should be connected before multi-user deployment.
