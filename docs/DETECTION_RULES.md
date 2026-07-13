# Detection Rules

Packsight rules are evidence-led. Severity is not calculated from keywords alone, and exploitability is never claimed without strong evidence.

## Evidence Classes

- `confirmed_fact`: exact chain, source, lockfile, or advisory data.
- `static_analysis`: parser-derived source or manifest finding.
- `heuristic`: name, comment, or pattern signal that needs review.
- `missing_information`: unavailable source, historical data, interface, or dependency coverage.
- `manual_review`: governance or configuration concern requiring human context.

## Severity Model

- `critical`: strong evidence that deprecated or legacy code is callable, can directly move/control valuable assets, lacks required authorization, and confidence is high or confirmed.
- `high`: sensitive legacy logic remains callable but exploitability needs review; old implementation remains initializable; unsafe storage-layout change is confirmed.
- `medium`: deprecated state-changing instruction remains exposed; old package/program address remains referenced; weakly governed upgrade authority; missing source verification.
- `low`: missing lockfile, stale metadata, deprecated dev dependency, version fragmentation.
- `info`: proxy or upgradeability detected, source unavailable, manual review required.

## Confidence Model

- `confirmed`: directly proven using on-chain data or exact source/deployment comparison.
- `high`: supported by multiple independent signals.
- `medium`: supported by static analysis but incomplete runtime data.
- `low`: heuristic or based on names/comments only.

## Sui Rules

### SUI-VERSION-001: Legacy package version remains callable

Reports an older package ID that remains referenced by source/configuration or chain metadata. This is not automatically a vulnerability; it becomes more severe when sensitive callable surface remains exposed.

### SUI-VERSION-002: Sensitive legacy entry function lacks an observable version gate

Reports a public or entry function in source that appears legacy/deprecated, mutates sensitive state, and does not show an observable version assertion in available source.

### SUI-VERSION-003: Shared object version is not validated

Reports source that defines version state but sensitive public/entry functions do not appear to compare it against an expected version.

### SUI-VERSION-004: Migration does not disable legacy path

Reports migration functions or comments alongside legacy callable paths that remain present. Confidence is lowered unless source proves the old path still mutates state after migration.

### SUI-VERSION-005: Old package address remains referenced

Reports old package IDs or addresses referenced in source, manifests, deployment records, or frontend/client files.

### SUI-VERSION-006: Sensitive legacy functions are still present in the upgraded package

Reports sensitive public or entry functions exposed by a legacy package that also exist in the latest package interface. This is an interface comparison, not proof that the old function can successfully mutate live state.

### SUI-LINKAGE-001: Linked packages changed in the upgraded package

Reports Sui linkage entries where the scanned package resolves an original package to a different version or upgraded package than the latest package. This helps auditors inspect stale dependency behavior in legacy packages.

### SUI-DEPS-001: Move.lock missing

Reports a Move package without `Move.lock`. This is a reproducibility finding, generally low severity.

### SUI-DEPS-002: Mutable Git dependency

Reports a Move Git dependency pinned to a branch, tag-like ref, or no revision instead of an immutable commit.

### SUI-DEPS-003: Package dependency address mismatch

Reports mismatches between declared package addresses and published records when both are available.

### SUI-UPGRADE-001: Upgrade authority configuration requires review

Reports upgrade authority or capability information that requires governance review. This is not automatically a vulnerability.

### SUI-SOURCE-001: Deployed package source could not be verified

Reports missing verified or supplied source. Source-dependent checks are marked incomplete.

## Solana Rules

### SOL-METADATA-001: Solana program metadata could not be fetched

Reports RPC failure or missing program account metadata. This is a coverage finding.

### SOL-UPGRADE-001: Upgradeable Solana program has an active upgrade authority

Reports a BPF upgradeable-loader program whose ProgramData account still records an upgrade authority. This is a governance-review signal, not proof of compromise.

### SOL-INTERFACE-001: Solana instruction interface is unavailable

Reports missing Anchor IDL or source-derived instruction metadata. Solana program accounts do not expose instruction names on-chain, so function-level analysis requires IDL/source.

## EVM Rules

### EVM-METADATA-001: EVM contract metadata could not be fetched

Reports RPC failure while fetching bytecode, block, chain ID or storage metadata.

### EVM-BYTECODE-001: Address has no deployed EVM bytecode

Reports an address that returns `0x` bytecode at the scan block.

### EVM-SOURCE-001: EVM ABI or verified source is unavailable

Reports missing ABI/source. Without ABI, packsight records only a wildcard contract surface.

### EVM-PROXY-001: EIP-1967 proxy storage slot is populated

Reports populated implementation or beacon storage slots and includes admin slot evidence when present. This indicates proxy-style upgradeability requiring governance and implementation review.

## Scoring

Packsight starts from 100 and applies capped deductions:

```text
critical -30
high     -15
medium   -7
low      -2
info      0
```

Confidence multiplier:

```text
confirmed 1.0
high      0.9
medium    0.6
low       0.3
```

The result is a security hygiene score, not an audit score.
