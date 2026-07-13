import type { MoveSourceAnalysis } from "@packsight/move-analyzer";
import type { Confidence, SecurityFinding, Severity } from "@packsight/report-schema";

export interface RuleDefinition {
  id: string;
  title: string;
  description: string;
  whyItMatters: string;
  detectionMethod: string;
  evidenceRequired: string[];
  falsePositiveConditions: string[];
  recommendation: string;
  supportedChains: Array<"sui" | "solana" | "evm">;
}

export const ruleDefinitions: RuleDefinition[] = [
  {
    id: "SUI-VERSION-001",
    title: "Legacy package version remains callable",
    description: "An older package version appears to remain reachable or referenced.",
    whyItMatters: "Sui package upgrades do not automatically make previous package IDs unreachable.",
    detectionMethod: "Compare package/source references and callable public or entry functions.",
    evidenceRequired: ["Package ID", "callable surface", "legacy reference or lineage signal"],
    falsePositiveConditions: ["The old package is intentionally retained and gated by state"],
    recommendation: "Disable legacy paths with observable version gates or remove stale references.",
    supportedChains: ["sui"]
  },
  {
    id: "SUI-VERSION-002",
    title: "Sensitive legacy entry function lacks version gate",
    description: "Deprecated or legacy state-changing entry logic lacks an observable version assertion.",
    whyItMatters: "Users may still interact with code the protocol intended to retire.",
    detectionMethod: "Parse Move source for deprecated markers, entry/public functions, state mutation, and guards.",
    evidenceRequired: ["Move source", "function location", "missing gate signal"],
    falsePositiveConditions: ["The gate is enforced in a helper pattern not recognized by the analyzer"],
    recommendation: "Add a shared-state version assertion that aborts stale package calls.",
    supportedChains: ["sui"]
  },
  {
    id: "SUI-VERSION-003",
    title: "Shared object version is not validated",
    description: "Version state exists but sensitive entry functions do not visibly validate it.",
    whyItMatters: "Version fields only reduce risk when sensitive call paths enforce them.",
    detectionMethod: "Detect version state and compare sensitive functions against recognized assertion patterns.",
    evidenceRequired: ["Move source", "version state signal", "sensitive function"],
    falsePositiveConditions: ["Validation occurs in a helper not visible to the heuristic"],
    recommendation: "Ensure every sensitive public or entry path checks the current expected version.",
    supportedChains: ["sui"]
  },
  {
    id: "SUI-VERSION-005",
    title: "Old package address remains referenced",
    description: "Source or configuration references a Sui package address that may represent an old deployment.",
    whyItMatters: "Client and deployment references can keep legacy code reachable in practice.",
    detectionMethod: "Search source and manifests for package-like addresses.",
    evidenceRequired: ["Referenced address", "file path"],
    falsePositiveConditions: ["The address is a framework package or documented historical reference"],
    recommendation: "Review and remove stale package IDs from clients, manifests, and deployment records.",
    supportedChains: ["sui"]
  },
  {
    id: "SUI-VERSION-006",
    title: "Sensitive legacy functions are still present in the upgraded package",
    description: "Sensitive functions exposed by a legacy package also exist in the latest package interface.",
    whyItMatters: "If old package state paths remain accepted, users may execute older copies of maintained sensitive logic.",
    detectionMethod: "Compare legacy package functions against latest package functions by module and function name.",
    evidenceRequired: ["Legacy package ID", "latest package ID", "function diff"],
    falsePositiveConditions: ["The old package functions are intentionally retained but blocked by state/version guards"],
    recommendation: "Review version gates and simulate sensitive old-package calls with production-like state.",
    supportedChains: ["sui"]
  },
  {
    id: "SUI-LINKAGE-001",
    title: "Linked packages changed in the upgraded package",
    description: "A legacy package resolves one or more linked packages differently than the latest package.",
    whyItMatters: "Legacy packages can remain compiled against older linked package resolutions.",
    detectionMethod: "Compare Sui Move package linkage entries between scanned and latest package versions.",
    evidenceRequired: ["Original package ID", "legacy resolved package", "latest resolved package"],
    falsePositiveConditions: ["The old linked package is intentionally retained and has no state-impacting behavior"],
    recommendation: "Review changed linkage entries and verify legacy functions cannot depend on stale dependency behavior.",
    supportedChains: ["sui"]
  },
  {
    id: "SUI-SOURCE-001",
    title: "Deployed package source could not be verified",
    description: "No source was supplied or verified, so source-level checks could not run.",
    whyItMatters: "Missing source lowers confidence for version-gate and deprecation checks.",
    detectionMethod: "Check whether source files were supplied and parsed.",
    evidenceRequired: ["Missing source signal"],
    falsePositiveConditions: ["Source is available through a provider not configured for this scan"],
    recommendation: "Supply the exact published source or verified repository commit.",
    supportedChains: ["sui"]
  },
  {
    id: "SOL-METADATA-001",
    title: "Solana program metadata could not be fetched",
    description: "The configured Solana RPC endpoint did not return program account metadata.",
    whyItMatters: "Auditors need account ownership, executable status, and upgradeability facts before reviewing a program.",
    detectionMethod: "Call getAccountInfo for the program account and parse the RPC response.",
    evidenceRequired: ["Program ID", "RPC endpoint", "RPC error"],
    falsePositiveConditions: ["Wrong network selected", "RPC endpoint unavailable or rate-limited"],
    recommendation: "Retry with a reliable RPC endpoint and confirm the target network.",
    supportedChains: ["solana"]
  },
  {
    id: "SOL-UPGRADE-001",
    title: "Upgradeable Solana program has an active upgrade authority",
    description: "The program is owned by the BPF upgradeable loader and the ProgramData account records an authority.",
    whyItMatters: "An upgrade authority can replace executable logic, so custody and governance are audit-critical.",
    detectionMethod: "Parse BPF upgradeable loader Program and ProgramData account state.",
    evidenceRequired: ["Program owner", "ProgramData account", "upgrade authority"],
    falsePositiveConditions: ["The authority is intentionally controlled by audited governance"],
    recommendation: "Review upgrade authority custody, timelocks, and finalization policy.",
    supportedChains: ["solana"]
  },
  {
    id: "SOL-INTERFACE-001",
    title: "Solana instruction interface is unavailable",
    description: "No IDL or source-derived instruction list was available for the scanned program.",
    whyItMatters: "Solana program accounts do not expose instruction names, so auditors need IDL/source for function-level checks.",
    detectionMethod: "Look for Anchor IDL files under sourcePath and fall back to wildcard program surface.",
    evidenceRequired: ["Program ID", "source/IDL availability"],
    falsePositiveConditions: ["The program does not use Anchor or the IDL is stored elsewhere"],
    recommendation: "Provide the verified repository, Anchor IDL, or generated interface metadata.",
    supportedChains: ["solana"]
  },
  {
    id: "EVM-METADATA-001",
    title: "EVM contract metadata could not be fetched",
    description: "The configured EVM RPC endpoint did not return bytecode or storage metadata.",
    whyItMatters: "Bytecode and storage facts are required to identify contracts, proxies, and scan block context.",
    detectionMethod: "Call eth_getCode, eth_blockNumber, eth_chainId, and selected storage slots.",
    evidenceRequired: ["Contract address", "RPC endpoint", "RPC error"],
    falsePositiveConditions: ["Wrong network selected", "RPC endpoint unavailable or rate-limited"],
    recommendation: "Retry with a reliable RPC endpoint and confirm the target network.",
    supportedChains: ["evm"]
  },
  {
    id: "EVM-BYTECODE-001",
    title: "Address has no deployed EVM bytecode",
    description: "The scanned address returned empty bytecode at the scan block.",
    whyItMatters: "An empty-code address is not auditable as a deployed contract on the selected network.",
    detectionMethod: "Call eth_getCode at latest.",
    evidenceRequired: ["Contract address", "bytecode result"],
    falsePositiveConditions: ["The contract was deployed on another network or self-destructed historically"],
    recommendation: "Confirm the target network and contract address.",
    supportedChains: ["evm"]
  },
  {
    id: "EVM-SOURCE-001",
    title: "EVM ABI or verified source is unavailable",
    description: "No ABI was found locally or through explorer metadata.",
    whyItMatters: "Function-level audit output requires an ABI or verified source.",
    detectionMethod: "Read local abi.json or query configured explorer metadata.",
    evidenceRequired: ["Contract address", "ABI/source availability"],
    falsePositiveConditions: ["ABI exists in a path packsight was not given"],
    recommendation: "Provide abi.json, verified source, or configure explorer API access.",
    supportedChains: ["evm"]
  },
  {
    id: "EVM-PROXY-001",
    title: "EIP-1967 proxy storage slot is populated",
    description: "The contract has EIP-1967 implementation or beacon storage populated.",
    whyItMatters: "Proxy upgradeability changes what code is active and who can alter it.",
    detectionMethod: "Read EIP-1967 implementation, beacon, and admin storage slots.",
    evidenceRequired: ["Implementation or beacon address", "admin address if present"],
    falsePositiveConditions: ["The proxy is intentionally governed and upgrade history is reviewed"],
    recommendation: "Review proxy admin ownership, timelocks, upgrade events, and implementation source.",
    supportedChains: ["evm"]
  }
];

export function getRule(id: string): RuleDefinition | undefined {
  return ruleDefinitions.find((rule) => rule.id === id);
}

const severityDeduction: Record<Severity, number> = {
  critical: 30,
  high: 15,
  medium: 7,
  low: 2,
  info: 0
};

const confidenceMultiplier: Record<Confidence, number> = {
  confirmed: 1,
  high: 0.9,
  medium: 0.6,
  low: 0.3
};

export function scoreFindings(findings: SecurityFinding[]): { score: number; grade: "A" | "B" | "C" | "D" | "F" } {
  const grouped = new Map<string, number>();
  for (const finding of findings) {
    const category = finding.ruleId.split("-").slice(0, 2).join("-");
    const deduction = severityDeduction[finding.severity] * confidenceMultiplier[finding.confidence];
    grouped.set(category, Math.max(grouped.get(category) ?? 0, deduction));
  }

  const totalDeduction = [...grouped.values()].reduce((sum, deduction) => sum + deduction, 0);
  const score = Math.max(0, Math.round(100 - totalDeduction));
  return { score, grade: gradeFor(score) };
}

function gradeFor(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function evaluateSuiSourceRules(analysis: MoveSourceAnalysis): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  if (analysis.sourceFiles.length === 0) {
    findings.push({
      ruleId: "SUI-SOURCE-001",
      title: "Deployed package source could not be verified",
      description:
        "No Move source was supplied, so Packsight could not confirm deprecation markers, callable functions, or version gates.",
      severity: "info",
      confidence: "confirmed",
      status: "open",
      chainFamily: "sui",
      evidence: [{ type: "missing_information", value: "sources/**/*.move unavailable" }],
      affectedComponents: [],
      impact: "Source-dependent checks are incomplete.",
      recommendation: "Provide the exact source archive, verified repository commit, Move.toml, and Move.lock.",
      limitations: ["On-chain package metadata alone cannot prove source-level version gating."]
    });
  }

  for (const fn of analysis.functions) {
    const callable = fn.entry || fn.visibility.includes("public");
    if (!callable) {
      continue;
    }

    const component = `${fn.moduleName}::${fn.functionName}`;
    if (fn.deprecated === true && fn.mutatesState === true && fn.valueSensitive === true && !fn.hasVersionGate) {
      findings.push({
        ruleId: "SUI-VERSION-002",
        title: "Sensitive legacy entry function lacks an observable version gate",
        description:
          "A deprecated or legacy callable Move function appears to mutate sensitive state, and no recognized version assertion was found in the available source.",
        severity: "high",
        confidence: "medium",
        status: "open",
        chainFamily: "sui",
        evidence: [
          {
            type: "source_location",
            value: component,
            file: fn.file,
            lineStart: fn.lineStart,
            lineEnd: fn.lineEnd
          },
          {
            type: "static_analysis",
            value: "deprecated marker + sensitive mutation + missing recognized version gate"
          }
        ],
        affectedComponents: [component],
        impact: "Users may still be able to interact with logic the protocol intended to retire.",
        recommendation:
          "Add a shared-state version assertion that aborts calls through legacy package logic and test that old entry functions cannot mutate protocol state.",
        limitations: ["The scanner did not simulate this function with production state."]
      });
    }

    if (analysis.hasVersionState && fn.valueSensitive === true && fn.mutatesState === true && !fn.hasVersionGate) {
      findings.push({
        ruleId: "SUI-VERSION-003",
        title: "Shared object version is not validated",
        description:
          "The package appears to define version state, but a sensitive state-changing callable function does not contain a recognized version assertion.",
        severity: "medium",
        confidence: "medium",
        status: "open",
        chainFamily: "sui",
        evidence: [
          {
            type: "source_location",
            value: component,
            file: fn.file,
            lineStart: fn.lineStart,
            lineEnd: fn.lineEnd
          }
        ],
        affectedComponents: [component],
        impact: "Version fields may not protect this call path if validation is absent.",
        recommendation: "Validate expected package or object version before sensitive state changes.",
        limitations: ["Helper-based gates can require manual review."]
      });
    }
  }

  for (const address of analysis.oldPackageReferences) {
    findings.push({
      ruleId: "SUI-VERSION-005",
      title: "Old package address remains referenced",
      description:
        "A package-like Sui address remains present in source. This may be a framework address, active package ID, or stale deployment reference and requires review.",
      severity: "medium",
      confidence: "low",
      status: "open",
      chainFamily: "sui",
      evidence: [{ type: "heuristic", value: address }],
      affectedComponents: [address],
      impact: "Client or configuration references can keep legacy package versions reachable in practice.",
      recommendation: "Review the address and remove or document stale package references.",
      limitations: ["Address role cannot be confirmed from source text alone."]
    });
  }

  return dedupeFindings(findings);
}

function dedupeFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.ruleId}:${finding.affectedComponents.join(",")}:${finding.evidence
      .map((item) => item.value)
      .join(",")}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
