import { access, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  CallableSurface,
  CodeVersion,
  DataCoverage,
  DependencyRecord,
  Evidence,
  PackageLink,
  RuntimeCheck,
  ScanTarget,
  SecurityFinding,
  VersionFunctionDiff
} from "@packsight/report-schema";

export interface SolanaScanInput {
  network: string;
  programId: string;
  repositoryUrl?: string;
  commitSha?: string;
  sourcePath?: string;
  customRpcUrl?: string;
}

export interface SolanaScanArtifacts {
  target: ScanTarget;
  versions: CodeVersion[];
  callableSurface: CallableSurface[];
  versionFunctionDiffs: VersionFunctionDiff[];
  packageLinks: PackageLink[];
  runtimeChecks: RuntimeCheck[];
  dependencies: DependencyRecord[];
  findings: SecurityFinding[];
  dataCoverage: DataCoverage;
  evidence: Evidence[];
  scanPoint?: {
    slot?: string;
    rpcUrl?: string;
  };
}

interface SolanaProgramMetadata {
  programId: string;
  owner?: string;
  executable: boolean;
  lamports?: number;
  dataLength?: number;
  programDataAddress?: string;
  deployedSlot?: string;
  upgradeAuthority?: string | null;
  slot?: string;
  endpoint?: string;
  fetched: boolean;
  error?: string;
}

interface AnchorIdlInstruction {
  name?: string;
  discriminator?: number[];
  accounts?: unknown[];
  args?: unknown[];
}

const solanaAddress = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const upgradeableLoader = "BPFLoaderUpgradeab1e11111111111111111111111";

const defaultRpcEndpoints: Record<string, string> = {
  mainnet: process.env.SOLANA_MAINNET_RPC_URL ?? "https://api.mainnet-beta.solana.com",
  "mainnet-beta": process.env.SOLANA_MAINNET_RPC_URL ?? "https://api.mainnet-beta.solana.com",
  testnet: process.env.SOLANA_TESTNET_RPC_URL ?? "https://api.testnet.solana.com",
  devnet: process.env.SOLANA_DEVNET_RPC_URL ?? "https://api.devnet.solana.com"
};

export async function scanSolanaProgram(input: SolanaScanInput): Promise<SolanaScanArtifacts> {
  const programId = input.programId.trim();
  if (!solanaAddress.test(programId)) {
    throw new Error("Invalid Solana program ID. Expected a base58 public key.");
  }

  const target: ScanTarget = {
    chainFamily: "solana",
    network: input.network,
    address: programId,
    ...(input.repositoryUrl ? { repositoryUrl: input.repositoryUrl } : {}),
    ...(input.commitSha ? { commitSha: input.commitSha } : {})
  };

  const metadata = await fetchSolanaProgramMetadata({
    network: input.network,
    programId,
    ...(input.customRpcUrl ? { customRpcUrl: input.customRpcUrl } : {})
  });
  const sourceAvailable = input.sourcePath ? await exists(input.sourcePath) : false;
  const idlInstructions = sourceAvailable ? await readAnchorIdlInstructions(input.sourcePath as string) : [];
  const callableSurface = idlInstructions.length > 0 ? anchorCallableSurface(programId, idlInstructions) : fallbackCallableSurface(programId);
  const findings = [
    ...metadataFindings(metadata),
    ...upgradeAuthorityFindings(metadata),
    ...interfaceFindings(metadata, idlInstructions, sourceAvailable)
  ];
  const currentVersion: CodeVersion = {
    identifier: metadata.deployedSlot ?? metadata.owner ?? programId,
    ...(metadata.deployedSlot ? { version: `slot:${metadata.deployedSlot}` } : {}),
    address: programId,
    verified: sourceAvailable,
    activeStatus: "active"
  };

  return {
    target,
    versions: [currentVersion],
    callableSurface,
    versionFunctionDiffs: [],
    packageLinks: [],
    runtimeChecks: [],
    dependencies: [],
    findings,
    dataCoverage: {
      onchainMetadata: metadata.fetched ? "partial" : "unavailable",
      sourceCode: sourceAvailable ? "partial" : "unavailable",
      historicalVersions: metadata.deployedSlot ? "partial" : "unavailable",
      interfaceData: idlInstructions.length > 0 ? "complete" : "unavailable",
      dependencyGraph: "unavailable",
      runtimeReachability: "not_tested"
    },
    evidence: [
      {
        type: metadata.fetched ? "rpc_response" : "missing_information",
        value: metadata.fetched
          ? `Fetched Solana program metadata for ${programId}`
          : `Could not fetch Solana program metadata: ${metadata.error ?? "unknown error"}`,
        source: "onchain"
      },
      ...(metadata.programDataAddress
        ? [
            {
              type: "programdata_account",
              value: metadata.programDataAddress,
              source: "onchain" as const
            }
          ]
        : [])
    ],
    scanPoint: {
      ...(metadata.slot ? { slot: metadata.slot } : {}),
      ...(metadata.endpoint ? { rpcUrl: metadata.endpoint } : {})
    }
  };
}

export function resolveSolanaRpcUrl(network: string, customRpcUrl?: string): string {
  if (customRpcUrl) return customRpcUrl;
  if (network.startsWith("http")) return network;
  return defaultRpcEndpoints[network] ?? network;
}

async function fetchSolanaProgramMetadata(input: {
  network: string;
  programId: string;
  customRpcUrl?: string;
}): Promise<SolanaProgramMetadata> {
  const endpoint = resolveSolanaRpcUrl(input.network, input.customRpcUrl);
  if (!endpoint.startsWith("http")) {
    return emptyMetadata(input.programId, "No RPC endpoint configured for custom Solana network", endpoint);
  }

  try {
    const account = await rpc<{ context?: { slot?: number }; value?: SolanaAccount | null }>(endpoint, "getAccountInfo", [
      input.programId,
      { encoding: "base64", commitment: "finalized" }
    ]);
    if (!account.value) {
      return emptyMetadata(input.programId, "Program account not found", endpoint, account.context?.slot);
    }

    const metadata: SolanaProgramMetadata = {
      programId: input.programId,
      executable: Boolean(account.value.executable),
      endpoint,
      fetched: true
    };
    if (account.value.owner) metadata.owner = account.value.owner;
    if (account.value.lamports !== undefined) metadata.lamports = account.value.lamports;
    const dataLength = accountData(account.value)?.length;
    if (dataLength !== undefined) metadata.dataLength = dataLength;
    if (account.context?.slot !== undefined) metadata.slot = String(account.context.slot);

    if (account.value.owner === upgradeableLoader) {
      const parsedProgram = parseUpgradeableProgram(accountData(account.value));
      if (parsedProgram.programDataAddress) {
        metadata.programDataAddress = parsedProgram.programDataAddress;
        const programData = await rpc<{ context?: { slot?: number }; value?: SolanaAccount | null }>(endpoint, "getAccountInfo", [
          parsedProgram.programDataAddress,
          { encoding: "base64", commitment: "finalized" }
        ]);
        const parsedProgramData = parseUpgradeableProgramData(accountData(programData.value));
        if (parsedProgramData.slot) metadata.deployedSlot = parsedProgramData.slot;
        if (parsedProgramData.upgradeAuthority !== undefined) metadata.upgradeAuthority = parsedProgramData.upgradeAuthority;
        if (programData.context?.slot !== undefined) metadata.slot = String(programData.context.slot);
      }
    }

    return metadata;
  } catch (error) {
    return emptyMetadata(input.programId, error instanceof Error ? error.message : "unknown fetch error", endpoint);
  }
}

interface SolanaAccount {
  data?: [string, string] | string[];
  executable?: boolean;
  lamports?: number;
  owner?: string;
}

async function rpc<T>(endpoint: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: `packsight-${Date.now()}`, method, params })
  });
  if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
  const payload = (await response.json()) as { result?: T; error?: { message?: string } };
  if (payload.error) throw new Error(payload.error.message ?? "Solana RPC error");
  return payload.result as T;
}

function accountData(account?: SolanaAccount | null): Buffer | undefined {
  const encoded = Array.isArray(account?.data) ? account.data[0] : undefined;
  return typeof encoded === "string" ? Buffer.from(encoded, "base64") : undefined;
}

function parseUpgradeableProgram(data?: Buffer): { programDataAddress?: string } {
  if (!data || data.length < 36 || data.readUInt32LE(0) !== 2) return {};
  return { programDataAddress: base58Encode(data.subarray(4, 36)) };
}

function parseUpgradeableProgramData(data?: Buffer): { slot?: string; upgradeAuthority?: string | null } {
  if (!data || data.length < 16 || data.readUInt32LE(0) !== 3) return {};
  const slot = data.readBigUInt64LE(4).toString();
  const option = data.readUInt32LE(12);
  if (option === 0) return { slot, upgradeAuthority: null };
  if (option === 1 && data.length >= 48) return { slot, upgradeAuthority: base58Encode(data.subarray(16, 48)) };
  return { slot };
}

async function readAnchorIdlInstructions(sourcePath: string): Promise<AnchorIdlInstruction[]> {
  const candidates = [join(sourcePath, "target", "idl"), join(sourcePath, "idl")];
  const instructions: AnchorIdlInstruction[] = [];
  for (const candidate of candidates) {
    if (!(await exists(candidate))) continue;
    for (const file of await readdir(candidate)) {
      if (!file.endsWith(".json")) continue;
      const parsed = JSON.parse(await readFile(join(candidate, file), "utf8")) as { instructions?: AnchorIdlInstruction[] };
      instructions.push(...(parsed.instructions ?? []));
    }
  }
  return instructions;
}

function anchorCallableSurface(programId: string, instructions: AnchorIdlInstruction[]): CallableSurface[] {
  return instructions
    .filter((instruction) => instruction.name)
    .map((instruction): CallableSurface => ({
      name: instruction.name as string,
      selector: instruction.discriminator?.join(","),
      address: programId,
      visibility: "anchor_instruction",
      deprecated: "unknown",
      reachable: "unknown",
      mutatesState: "unknown",
      valueSensitive: isSensitiveInstructionName(instruction.name as string)
    }));
}

function fallbackCallableSurface(programId: string): CallableSurface[] {
  return [
    {
      name: `${programId}::*`,
      address: programId,
      visibility: "instruction_interface_unknown",
      deprecated: "unknown",
      reachable: "unknown",
      mutatesState: "unknown",
      valueSensitive: "unknown"
    }
  ];
}

function metadataFindings(metadata: SolanaProgramMetadata): SecurityFinding[] {
  if (metadata.fetched) return [];
  return [
    {
      ruleId: "SOL-METADATA-001",
      title: "Solana program metadata could not be fetched",
      description: "Packsight could not fetch program account metadata from the configured Solana RPC endpoint.",
      severity: "info",
      confidence: "confirmed",
      status: "open",
      chainFamily: "solana",
      evidence: [{ type: "missing_information", value: metadata.error ?? "Solana RPC metadata unavailable" }],
      affectedComponents: [metadata.programId],
      impact: "Program ownership, upgradeability, and deployment-slot coverage are unavailable.",
      recommendation: "Retry with a reachable Solana RPC endpoint or provide a custom RPC URL.",
      limitations: ["This is a coverage finding, not proof of exploitability."]
    }
  ];
}

function upgradeAuthorityFindings(metadata: SolanaProgramMetadata): SecurityFinding[] {
  if (!metadata.fetched || metadata.owner !== upgradeableLoader || metadata.upgradeAuthority === undefined) return [];
  if (metadata.upgradeAuthority === null) return [];
  return [
    {
      ruleId: "SOL-UPGRADE-001",
      title: "Upgradeable Solana program has an active upgrade authority",
      description: "The program is owned by the BPF upgradeable loader and its ProgramData account still records an upgrade authority.",
      severity: "medium",
      confidence: "high",
      status: "open",
      chainFamily: "solana",
      evidence: [
        { type: "program_owner", value: metadata.owner, source: "onchain" },
        { type: "upgrade_authority", value: metadata.upgradeAuthority, source: "onchain" }
      ],
      affectedComponents: [metadata.programId],
      impact: "The deployed executable can be replaced by the upgrade authority unless governance or operational controls constrain it.",
      recommendation: "Review upgrade authority custody, governance timelocks, and whether the program should be finalized.",
      limitations: ["The scanner does not prove the authority key is compromised or unsafe."]
    }
  ];
}

function interfaceFindings(
  metadata: SolanaProgramMetadata,
  idlInstructions: AnchorIdlInstruction[],
  sourceAvailable: boolean
): SecurityFinding[] {
  if (!metadata.fetched || idlInstructions.length > 0) return [];
  return [
    {
      ruleId: "SOL-INTERFACE-001",
      title: "Solana instruction interface is unavailable",
      description:
        "No Anchor IDL or source-derived instruction list was available, so packsight cannot enumerate deprecated or sensitive instructions.",
      severity: "info",
      confidence: "confirmed",
      status: "open",
      chainFamily: "solana",
      evidence: [{ type: "missing_information", value: sourceAvailable ? "Anchor IDL not found" : "sourcePath unavailable" }],
      affectedComponents: [metadata.programId],
      impact: "Callable instruction coverage is limited to a wildcard program surface.",
      recommendation: "Provide the verified repository or Anchor IDL for instruction-level audit output.",
      limitations: ["Solana program accounts do not expose instruction names on-chain."]
    }
  ];
}

function isSensitiveInstructionName(name: string): boolean | "unknown" {
  return /\b(withdraw|admin|authority|upgrade|mint|burn|transfer|claim|vault|fee|sweep|pause)\b/i.test(name.replace(/_/g, " "))
    ? true
    : "unknown";
}

function emptyMetadata(programId: string, error: string, endpoint?: string, slot?: number): SolanaProgramMetadata {
  return {
    programId,
    executable: false,
    ...(slot === undefined ? {} : { slot: String(slot) }),
    ...(endpoint ? { endpoint } : {}),
    fetched: false,
    error
  };
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes: Buffer): string {
  let value = BigInt(`0x${bytes.toString("hex") || "0"}`);
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    value /= 58n;
    encoded = base58Alphabet[remainder]! + encoded;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = base58Alphabet[0]! + encoded;
  }
  return encoded || base58Alphabet[0]!;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
