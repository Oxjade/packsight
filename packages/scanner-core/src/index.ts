import { scanEvmContract } from "@packsight/adapter-evm";
import { scanSolanaProgram } from "@packsight/adapter-solana";
import { scanSuiPackage } from "@packsight/adapter-sui";
import type { ScanReport, ScanStage, SecurityFinding } from "@packsight/report-schema";
import { scoreFindings } from "@packsight/rule-engine";
import { createScanRequestSchema, type CreateScanRequest } from "@packsight/shared";

export interface RunScanOptions {
  id: string;
  request: CreateScanRequest;
  onStage?: (stage: ScanStage) => void | Promise<void>;
}

export async function runScan(options: RunScanOptions): Promise<ScanReport> {
  const request = createScanRequestSchema.parse(options.request);
  const startedAt = new Date().toISOString();

  await options.onStage?.("validating_input");

  await options.onStage?.("fetching_chain_metadata");
  const scanResult = await runChainScan(request);

  await options.onStage?.("resolving_versions");
  await options.onStage?.("resolving_source");
  await options.onStage?.("analyzing_callable_surface");
  await options.onStage?.("scanning_dependencies");
  await options.onStage?.("evaluating_findings");
  const scored = scoreFindings(scanResult.findings);
  await options.onStage?.("generating_report");

  const report: ScanReport = {
    id: options.id,
    target: {
      chainFamily: request.chainFamily,
      network: request.network,
      chainId: request.chainId,
      address: request.address,
      repositoryUrl: request.repositoryUrl,
      commitSha: request.commitSha
    },
    startedAt,
    completedAt: new Date().toISOString(),
    status: "completed",
    score: scored.score,
    grade: scored.grade,
    summary: buildSummary(scanResult.findings, scanResult.callableSurface.length, request.chainFamily),
    versions: scanResult.versions,
    callableSurface: scanResult.callableSurface,
    versionFunctionDiffs: scanResult.versionFunctionDiffs,
    packageLinks: scanResult.packageLinks,
    runtimeChecks: scanResult.runtimeChecks,
    dependencies: scanResult.dependencies,
    findings: scanResult.findings,
    dataCoverage: scanResult.dataCoverage,
    scanPoint: {
      ...scanResult.scanPoint,
      ...(request.customGraphqlUrl || request.customRpcUrl ? { rpcUrl: request.customGraphqlUrl ?? request.customRpcUrl } : {}),
      ...(request.commitSha ? { sourceCommit: request.commitSha } : {})
    }
  };

  return report;
}

async function runChainScan(request: CreateScanRequest) {
  const commonInput = {
    network: request.network,
    ...(request.repositoryUrl ? { repositoryUrl: request.repositoryUrl } : {}),
    ...(request.commitSha ? { commitSha: request.commitSha } : {}),
    ...(request.sourcePath ? { sourcePath: request.sourcePath } : {}),
    ...(request.customRpcUrl ? { customRpcUrl: request.customRpcUrl } : {}),
    ...(request.chainId ? { chainId: request.chainId } : {})
  };

  if (request.chainFamily === "sui") {
    return scanSuiPackage({
      ...commonInput,
      packageId: request.address ?? "",
      ...(request.customGraphqlUrl ? { customGraphqlUrl: request.customGraphqlUrl } : {})
    });
  }

  if (request.chainFamily === "solana") {
    return scanSolanaProgram({
      ...commonInput,
      programId: request.address ?? ""
    });
  }

  return scanEvmContract({
    ...commonInput,
    contractAddress: request.address ?? ""
  });
}

function buildSummary(
  findings: ScanReport["findings"],
  callableCount: number,
  chainFamily: ScanReport["target"]["chainFamily"]
): ScanReport["summary"] {
  const confirmedFacts = findings
    .filter((finding) => finding.confidence === "confirmed")
    .slice(0, 4)
    .map((finding) => `${finding.ruleId}: ${finding.title}`);
  const staticAnalysisFindings = findings
    .filter((finding) => finding.confidence === "medium" || finding.confidence === "high")
    .slice(0, 4)
    .map((finding) => `${finding.ruleId}: ${finding.title}`);
  const heuristicFindings = findings
    .filter((finding) => finding.confidence === "low")
    .slice(0, 4)
    .map((finding) => `${finding.ruleId}: ${finding.title}`);

  return {
    headline:
      findings.length === 0
        ? `No findings were produced from the available data. ${callableCount} callable-surface records were observed.`
        : `${findings.length} finding${findings.length === 1 ? "" : "s"} produced from available ${chainFamily} target data.`,
    confirmedFacts,
    staticAnalysisFindings,
    heuristicFindings,
    missingInformation: [
      "Runtime reachability was not simulated.",
      chainFamily === "sui"
        ? "Historical package lineage is partial unless supplied source or chain data exposes it."
        : "Historical implementation, deployment or program lineage is partial unless supplied source or chain data exposes it."
    ],
    manualReviewRecommendations: [
      "Review upgrade authority and governance controls manually.",
      "Confirm any legacy or deprecated function against production state and authorization checks."
    ]
  };
}

export function calculateSecurityHygieneScore(findings: SecurityFinding[]): number {
  return scoreFindings(findings).score;
}

export function gradeFor(score: number): ScanReport["grade"] {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}
