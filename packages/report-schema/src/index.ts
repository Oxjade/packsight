import { z } from "zod";

export const chainFamilySchema = z.enum(["sui", "solana", "evm"]);
export const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export const confidenceSchema = z.enum(["low", "medium", "high", "confirmed"]);
export const findingStatusSchema = z.enum(["open", "accepted", "false_positive", "resolved"]);
export const coverageStateSchema = z.enum(["complete", "partial", "unavailable", "not_applicable", "not_tested"]);

export type ChainFamily = z.infer<typeof chainFamilySchema>;
export type Severity = z.infer<typeof severitySchema>;
export type Confidence = z.infer<typeof confidenceSchema>;
export type FindingStatus = z.infer<typeof findingStatusSchema>;
export type CoverageState = z.infer<typeof coverageStateSchema>;

export const evidenceSchema = z.object({
  type: z.string().min(1),
  value: z.string().min(1),
  file: z.string().optional(),
  lineStart: z.number().int().positive().optional(),
  lineEnd: z.number().int().positive().optional(),
  source: z.enum(["onchain", "verified_source", "repository", "manifest", "lockfile", "interface", "scanner"]).optional()
});

export type Evidence = z.infer<typeof evidenceSchema>;

export const scanTargetSchema = z.object({
  chainFamily: chainFamilySchema,
  network: z.string().min(1),
  chainId: z.string().optional(),
  address: z.string().optional(),
  repositoryUrl: z.string().url().optional(),
  commitSha: z.string().optional()
});

export type ScanTarget = z.infer<typeof scanTargetSchema>;

export const codeVersionSchema = z.object({
  identifier: z.string().min(1),
  version: z.string().optional(),
  address: z.string().optional(),
  deployedAt: z.string().optional(),
  transactionHash: z.string().optional(),
  sourceCommit: z.string().optional(),
  verified: z.boolean(),
  activeStatus: z.enum(["active", "legacy", "unknown"])
});

export type CodeVersion = z.infer<typeof codeVersionSchema>;

export const callableSurfaceSchema = z.object({
  name: z.string().min(1),
  selector: z.string().optional(),
  module: z.string().optional(),
  address: z.string().optional(),
  versionIdentifier: z.string().optional(),
  visibility: z.string().min(1),
  accessibility: z.enum(["transaction_entry", "public_move_call", "friend_only", "private", "unknown"]).optional(),
  accessibilityReason: z.string().optional(),
  deprecated: z.union([z.boolean(), z.literal("unknown")]),
  reachable: z.union([z.boolean(), z.literal("unknown")]),
  mutatesState: z.union([z.boolean(), z.literal("unknown")]),
  valueSensitive: z.union([z.boolean(), z.literal("unknown")])
});

export type CallableSurface = z.infer<typeof callableSurfaceSchema>;

export const versionFunctionDiffSchema = z.object({
  name: z.string().min(1),
  module: z.string().min(1),
  packageAddress: z.string().min(1),
  packageVersion: z.string().optional(),
  comparedToAddress: z.string().min(1),
  comparedToVersion: z.string().optional(),
  status: z.enum(["present_in_upgrade", "removed_in_upgrade", "added_in_upgrade"]),
  visibility: z.string().min(1),
  isEntry: z.boolean(),
  accessibility: z.enum(["transaction_entry", "public_move_call", "friend_only", "private", "unknown"]).optional(),
  accessibilityReason: z.string().optional(),
  valueSensitive: z.union([z.boolean(), z.literal("unknown")])
});

export type VersionFunctionDiff = z.infer<typeof versionFunctionDiffSchema>;

export const packageLinkSchema = z.object({
  sourcePackageAddress: z.string().min(1),
  sourcePackageVersion: z.string().optional(),
  originalPackageId: z.string().min(1),
  resolvedPackageId: z.string().min(1),
  resolvedVersion: z.string().optional(),
  latestResolvedPackageId: z.string().optional(),
  latestResolvedVersion: z.string().optional(),
  status: z.enum(["unchanged", "upgraded_in_latest", "missing_in_latest", "new_in_latest", "unknown"]),
  relationship: z.string().min(1),
  evidence: z.array(evidenceSchema)
});

export type PackageLink = z.infer<typeof packageLinkSchema>;

export const runtimeCheckSchema = z.object({
  functionName: z.string().min(1),
  module: z.string().optional(),
  packageAddress: z.string().min(1),
  packageVersion: z.string().optional(),
  accessibility: z.enum(["transaction_entry", "public_move_call", "friend_only", "private", "unknown"]),
  interfaceReachable: z.union([z.boolean(), z.literal("unknown")]),
  mutationRisk: z.enum(["state_mutation_likely", "state_mutation_possible", "read_only_likely", "unknown"]),
  guardStatus: z.enum(["source_guard_detected", "source_guard_missing", "unknown_source_unavailable", "not_applicable"]),
  runtimeStatus: z.enum(["simulation_required", "not_simulated", "blocked_by_interface", "aborted", "succeeded"]),
  parameters: z.array(z.string()),
  returns: z.array(z.string()),
  requiredEvidence: z.array(z.string()),
  notes: z.array(z.string())
});

export type RuntimeCheck = z.infer<typeof runtimeCheckSchema>;

export const advisoryReferenceSchema = z.object({
  id: z.string().min(1),
  source: z.string().min(1),
  url: z.string().url().optional(),
  severity: z.string().optional(),
  summary: z.string().optional()
});

export type AdvisoryReference = z.infer<typeof advisoryReferenceSchema>;

export const dependencyRecordSchema = z.object({
  ecosystem: z.enum(["npm", "cargo", "move", "git", "solidity"]),
  name: z.string().min(1),
  resolvedVersion: z.string().optional(),
  requestedVersion: z.string().optional(),
  source: z.string().optional(),
  direct: z.boolean(),
  deprecated: z.union([z.boolean(), z.literal("unknown")]),
  yanked: z.union([z.boolean(), z.literal("unknown")]),
  vulnerable: z.union([z.boolean(), z.literal("unknown")]),
  advisories: z.array(advisoryReferenceSchema)
});

export type DependencyRecord = z.infer<typeof dependencyRecordSchema>;

export const securityFindingSchema = z.object({
  ruleId: z.string().min(1),
  title: z.string().min(1),
  description: z.string().min(1),
  severity: severitySchema,
  confidence: confidenceSchema,
  status: findingStatusSchema.default("open"),
  chainFamily: chainFamilySchema.optional(),
  evidence: z.array(evidenceSchema),
  affectedComponents: z.array(z.string()),
  impact: z.string().min(1),
  recommendation: z.string().min(1),
  limitations: z.array(z.string()).optional(),
  references: z.array(z.string()).optional()
});

export type SecurityFinding = z.infer<typeof securityFindingSchema>;

export const reportSummarySchema = z.object({
  headline: z.string().min(1),
  confirmedFacts: z.array(z.string()),
  staticAnalysisFindings: z.array(z.string()),
  heuristicFindings: z.array(z.string()),
  missingInformation: z.array(z.string()),
  manualReviewRecommendations: z.array(z.string())
});

export type ReportSummary = z.infer<typeof reportSummarySchema>;

export const dataCoverageSchema = z.object({
  onchainMetadata: coverageStateSchema,
  sourceCode: coverageStateSchema,
  historicalVersions: coverageStateSchema,
  interfaceData: coverageStateSchema,
  dependencyGraph: coverageStateSchema,
  runtimeReachability: coverageStateSchema
});

export type DataCoverage = z.infer<typeof dataCoverageSchema>;

export const scanStageSchema = z.enum([
  "validating_input",
  "fetching_chain_metadata",
  "resolving_versions",
  "resolving_source",
  "analyzing_callable_surface",
  "scanning_dependencies",
  "evaluating_findings",
  "generating_report"
]);

export type ScanStage = z.infer<typeof scanStageSchema>;

export const scanReportSchema = z.object({
  id: z.string().min(1),
  target: scanTargetSchema,
  startedAt: z.string().min(1),
  completedAt: z.string().optional(),
  status: z.enum(["queued", "running", "completed", "failed"]),
  score: z.number().min(0).max(100),
  grade: z.enum(["A", "B", "C", "D", "F"]),
  summary: reportSummarySchema,
  versions: z.array(codeVersionSchema),
  callableSurface: z.array(callableSurfaceSchema),
  versionFunctionDiffs: z.array(versionFunctionDiffSchema),
  packageLinks: z.array(packageLinkSchema),
  runtimeChecks: z.array(runtimeCheckSchema),
  dependencies: z.array(dependencyRecordSchema),
  findings: z.array(securityFindingSchema),
  dataCoverage: dataCoverageSchema,
  scanPoint: z
    .object({
      chainCheckpoint: z.string().optional(),
      blockNumber: z.string().optional(),
      slot: z.string().optional(),
      chainId: z.string().optional(),
      sourceCommit: z.string().optional(),
      rpcUrl: z.string().optional()
    })
    .optional()
});

export type ScanReport = z.infer<typeof scanReportSchema>;

export const createScanRequestSchema = z
  .object({
    targetType: z.enum(["chain_address", "repository"]),
    chainFamily: chainFamilySchema,
    network: z.string().min(1),
    chainId: z.string().regex(/^\d+$/, "chainId must be a decimal EVM chain ID").optional(),
    address: z.string().optional(),
    repositoryUrl: z.string().url().optional(),
    commitSha: z.string().optional(),
    sourcePath: z.string().optional(),
    customGraphqlUrl: z.string().url().optional(),
    customRpcUrl: z.string().url().optional()
  })
  .superRefine((value, context) => {
    if (value.chainFamily === "evm" && !value.chainId) {
      context.addIssue({ code: "custom", message: "chainId is required for EVM scans", path: ["chainId"] });
    }
  });

export type CreateScanRequest = z.infer<typeof createScanRequestSchema>;

export const emptyCoverage: DataCoverage = {
  onchainMetadata: "unavailable",
  sourceCode: "unavailable",
  historicalVersions: "unavailable",
  interfaceData: "unavailable",
  dependencyGraph: "unavailable",
  runtimeReachability: "not_tested"
};
