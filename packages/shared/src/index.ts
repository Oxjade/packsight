import { z } from "zod";
import { chainFamilySchema, type ScanStage } from "@packsight/report-schema";

export const productName = "packsight";

export const targetTypeSchema = z.enum(["chain_address", "repository"]);

export const createScanRequestSchema = z
  .object({
    targetType: targetTypeSchema,
    chainFamily: chainFamilySchema,
    network: z.string().min(1),
    chainId: z.string().regex(/^\d+$/, "chainId must be a decimal EVM chain ID").optional(),
    address: z.string().optional(),
    repositoryUrl: z.string().url().optional(),
    commitSha: z.string().optional(),
    customGraphqlUrl: z.string().url().optional(),
    customRpcUrl: z.string().url().optional(),
    sourcePath: z.string().optional()
  })
  .superRefine((value, context) => {
    if (value.targetType === "chain_address" && !value.address) {
      context.addIssue({ code: "custom", message: "address is required for chain address scans", path: ["address"] });
    }

    if (value.chainFamily === "evm" && !value.chainId) {
      context.addIssue({ code: "custom", message: "chainId is required for EVM scans", path: ["chainId"] });
    }

    if (value.targetType === "repository" && !value.repositoryUrl && !value.sourcePath) {
      context.addIssue({
        code: "custom",
        message: "repositoryUrl or sourcePath is required for repository scans",
        path: ["repositoryUrl"]
      });
    }
  });

export type CreateScanRequest = z.infer<typeof createScanRequestSchema>;

export const progressStages = [
  "validating_input",
  "fetching_chain_metadata",
  "resolving_versions",
  "resolving_source",
  "analyzing_callable_surface",
  "scanning_dependencies",
  "evaluating_findings",
  "generating_report"
] as const satisfies readonly ScanStage[];

export const stageLabels: Record<ScanStage, string> = {
  validating_input: "Validating input",
  fetching_chain_metadata: "Fetching chain metadata",
  resolving_versions: "Resolving versions",
  resolving_source: "Resolving source",
  analyzing_callable_surface: "Analyzing callable surface",
  scanning_dependencies: "Scanning dependencies",
  evaluating_findings: "Evaluating findings",
  generating_report: "Generating report"
};

export function compactAddress(value: string): string {
  if (value.length <= 18) {
    return value;
  }
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

export function normalizeNetwork(network: string): string {
  return network.trim().toLowerCase();
}
