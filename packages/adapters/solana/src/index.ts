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

interface SolanaDeepDiscovery {
  fetched: boolean;
  signatureCount: number;
  sampledTransactionCount: number;
  cpiPrograms: DiscoveredSolanaNode[];
  accounts: DiscoveredSolanaNode[];
  error?: string;
}

interface DiscoveredSolanaNode {
  address: string;
  evidenceType: "recent_cpi_program" | "recent_instruction_account";
  signature: string;
}

interface AnchorIdlInstruction {
  name?: string;
  discriminator?: number[];
  accounts?: unknown[];
  args?: unknown[];
}

const solanaAddress = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const upgradeableLoader = "BPFLoaderUpgradeab1e11111111111111111111111";
const deepDiscoverySignatureLimit = 12;
const deepDiscoveryAccountLimit = 14;
const deepDiscoveryProgramLimit = 14;
const noisySolanaPrograms = new Set([
  "11111111111111111111111111111111",
  "ComputeBudget111111111111111111111111111111",
  "BPFLoader1111111111111111111111111111111111",
  "BPFLoader2111111111111111111111111111111111",
  upgradeableLoader
]);

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
  const currentVersion: CodeVersion = {
    identifier: metadata.deployedSlot ?? metadata.owner ?? programId,
    ...(metadata.deployedSlot ? { version: `slot:${metadata.deployedSlot}` } : {}),
    address: programId,
    verified: sourceAvailable,
    activeStatus: "active"
  };

  const deepDiscovery = await fetchSolanaDeepDiscovery(metadata, programId);
  const packageLinks = [...solanaAccountLinks(metadata), ...solanaDeepDiscoveryLinks(programId, deepDiscovery)];
  const findings = [
    ...metadataFindings(metadata),
    ...upgradeAuthorityFindings(metadata),
    ...interfaceFindings(metadata, idlInstructions, sourceAvailable),
    ...deepDiscoveryFindings(metadata, deepDiscovery)
  ];

  return {
    target,
    versions: [currentVersion],
    callableSurface,
    versionFunctionDiffs: [],
    packageLinks,
    runtimeChecks: [],
    dependencies: [],
    findings,
    dataCoverage: {
      onchainMetadata: metadata.fetched ? "partial" : "unavailable",
      sourceCode: sourceAvailable ? "partial" : "unavailable",
      historicalVersions: metadata.deployedSlot ? "partial" : "unavailable",
      interfaceData: idlInstructions.length > 0 ? "complete" : "unavailable",
      dependencyGraph: packageLinks.length > 0 ? "partial" : "unavailable",
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
        : []),
      ...(deepDiscovery.fetched
        ? [
            {
              type: "recent_transaction_sample",
              value: `${deepDiscovery.sampledTransactionCount} parsed transaction(s), ${deepDiscovery.cpiPrograms.length} CPI program(s), ${deepDiscovery.accounts.length} account(s)`,
              source: "onchain" as const
            }
          ]
        : deepDiscovery.error
          ? [
              {
                type: "deep_discovery_unavailable",
                value: deepDiscovery.error,
                source: "scanner" as const
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

function solanaAccountLinks(metadata: SolanaProgramMetadata): PackageLink[] {
  if (!metadata.fetched) return [];
  const evidence = (type: string, value: string): Evidence[] => [{ type, value, source: "onchain" }];
  const links: PackageLink[] = [];

  if (metadata.programDataAddress) {
    links.push({
      sourcePackageAddress: metadata.programId,
      sourcePackageVersion: metadata.deployedSlot,
      originalPackageId: metadata.programId,
      resolvedPackageId: metadata.programDataAddress,
      resolvedVersion: metadata.deployedSlot,
      status: "unchanged",
      relationship: "programdata_account",
      evidence: evidence("programdata_account", metadata.programDataAddress)
    });
  }

  if (metadata.programDataAddress && metadata.upgradeAuthority) {
    links.push({
      sourcePackageAddress: metadata.programDataAddress,
      sourcePackageVersion: metadata.deployedSlot,
      originalPackageId: metadata.programDataAddress,
      resolvedPackageId: metadata.upgradeAuthority,
      status: "unchanged",
      relationship: "upgrade_authority",
      evidence: evidence("upgrade_authority", metadata.upgradeAuthority)
    });
  }

  return links;
}

function solanaDeepDiscoveryLinks(programId: string, discovery: SolanaDeepDiscovery): PackageLink[] {
  if (!discovery.fetched) return [];
  const links: PackageLink[] = [];

  for (const discovered of discovery.cpiPrograms) {
    links.push({
      sourcePackageAddress: programId,
      originalPackageId: programId,
      resolvedPackageId: discovered.address,
      status: "unchanged",
      relationship: discovered.evidenceType,
      evidence: [{ type: discovered.evidenceType, value: discovered.signature, source: "onchain" }]
    });
  }

  for (const discovered of discovery.accounts) {
    links.push({
      sourcePackageAddress: programId,
      originalPackageId: programId,
      resolvedPackageId: discovered.address,
      status: "unchanged",
      relationship: discovered.evidenceType,
      evidence: [{ type: discovered.evidenceType, value: discovered.signature, source: "onchain" }]
    });
  }

  return links;
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

async function fetchSolanaDeepDiscovery(metadata: SolanaProgramMetadata, programId: string): Promise<SolanaDeepDiscovery> {
  if (!metadata.fetched || !metadata.endpoint) {
    return {
      fetched: false,
      signatureCount: 0,
      sampledTransactionCount: 0,
      cpiPrograms: [],
      accounts: []
    };
  }

  try {
    const signatures = await fetchRecentSignatures(metadata.endpoint, programId);
    const signatureValues = signatures.map((item) => item.signature).filter((value): value is string => Boolean(value));
    const cpiPrograms = new Map<string, DiscoveredSolanaNode>();
    const accounts = new Map<string, DiscoveredSolanaNode>();
    const transactionErrors: string[] = [];
    let sampledTransactionCount = 0;

    for (const signature of signatureValues) {
      const transaction = await fetchParsedTransaction(metadata.endpoint, signature, transactionErrors);
      if (!transaction) continue;
      sampledTransactionCount += 1;
      const discovered = extractTransactionDiscovery(transaction, programId, signature);

      for (const item of discovered.cpiPrograms) {
        if (cpiPrograms.size >= deepDiscoveryProgramLimit) break;
        if (!cpiPrograms.has(item.address)) cpiPrograms.set(item.address, item);
      }

      for (const item of discovered.accounts) {
        if (accounts.size >= deepDiscoveryAccountLimit) break;
        if (!accounts.has(item.address)) accounts.set(item.address, item);
      }

      if (cpiPrograms.size >= deepDiscoveryProgramLimit && accounts.size >= deepDiscoveryAccountLimit) break;
    }

    return {
      fetched: true,
      signatureCount: signatureValues.length,
      sampledTransactionCount,
      cpiPrograms: Array.from(cpiPrograms.values()),
      accounts: Array.from(accounts.values()),
      ...(transactionErrors.length > 0 ? { error: transactionErrors.slice(0, 2).join("; ") } : {})
    };
  } catch (error) {
    return {
      fetched: false,
      signatureCount: 0,
      sampledTransactionCount: 0,
      cpiPrograms: [],
      accounts: [],
      error: error instanceof Error ? error.message : "Solana deep discovery failed"
    };
  }
}

async function fetchRecentSignatures(endpoint: string, programId: string): Promise<Array<{ signature?: string }>> {
  try {
    return await rpc<Array<{ signature?: string }>>(endpoint, "getSignaturesForAddress", [
      programId,
      { commitment: "finalized", limit: deepDiscoverySignatureLimit }
    ]);
  } catch (error) {
    if (!isRateLimitError(error)) throw error;
    await sleep(700);
    return rpc<Array<{ signature?: string }>>(endpoint, "getSignaturesForAddress", [
      programId,
      { commitment: "finalized", limit: 4 }
    ]);
  }
}

async function fetchParsedTransaction(
  endpoint: string,
  signature: string,
  errors: string[]
): Promise<ParsedSolanaTransaction | null> {
  try {
    return await rpc<ParsedSolanaTransaction | null>(endpoint, "getTransaction", [
      signature,
      { commitment: "finalized", encoding: "jsonParsed", maxSupportedTransactionVersion: 0 }
    ]);
  } catch (error) {
    errors.push(`${signature}: ${error instanceof Error ? error.message : "transaction fetch failed"}`);
    if (isRateLimitError(error)) await sleep(300);
    return null;
  }
}

interface ParsedSolanaTransaction {
  transaction?: {
    message?: {
      accountKeys?: Array<string | { pubkey?: string }>;
      instructions?: ParsedSolanaInstruction[];
    };
  };
  meta?: {
    innerInstructions?: Array<{ instructions?: ParsedSolanaInstruction[] }>;
  };
}

interface ParsedSolanaInstruction {
  programId?: string;
  accounts?: string[];
  parsed?: unknown;
}

function extractTransactionDiscovery(
  transaction: ParsedSolanaTransaction,
  targetProgramId: string,
  signature: string
): { cpiPrograms: DiscoveredSolanaNode[]; accounts: DiscoveredSolanaNode[] } {
  const instructions = [
    ...(transaction.transaction?.message?.instructions ?? []),
    ...(transaction.meta?.innerInstructions ?? []).flatMap((group) => group.instructions ?? [])
  ];
  const programIds = new Set<string>();
  const accounts = new Set<string>();

  for (const instruction of instructions) {
    if (isDiscoverableSolanaAddress(instruction.programId, targetProgramId)) {
      programIds.add(instruction.programId);
    }

    for (const account of instruction.accounts ?? []) {
      if (isDiscoverableSolanaAddress(account, targetProgramId)) accounts.add(account);
    }

    for (const account of parsedInstructionAccounts(instruction.parsed)) {
      if (isDiscoverableSolanaAddress(account, targetProgramId)) accounts.add(account);
    }
  }

  for (const accountKey of transaction.transaction?.message?.accountKeys ?? []) {
    const key = typeof accountKey === "string" ? accountKey : accountKey.pubkey;
    if (isDiscoverableSolanaAddress(key, targetProgramId) && !programIds.has(key)) accounts.add(key);
  }

  for (const programId of programIds) accounts.delete(programId);

  return {
    cpiPrograms: Array.from(programIds).map((address) => ({ address, evidenceType: "recent_cpi_program", signature })),
    accounts: Array.from(accounts).map((address) => ({ address, evidenceType: "recent_instruction_account", signature }))
  };
}

function parsedInstructionAccounts(parsed: unknown): string[] {
  if (!parsed || typeof parsed !== "object") return [];
  const values: string[] = [];
  collectSolanaAddresses(parsed, values, 0);
  return values;
}

function collectSolanaAddresses(value: unknown, values: string[], depth: number): void {
  if (depth > 4 || values.length > 32) return;
  if (typeof value === "string") {
    if (solanaAddress.test(value)) values.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectSolanaAddresses(item, values, depth + 1);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const item of Object.values(value as Record<string, unknown>)) {
    collectSolanaAddresses(item, values, depth + 1);
  }
}

function isDiscoverableSolanaAddress(address: string | undefined, targetProgramId: string): address is string {
  if (!address || address === targetProgramId || !solanaAddress.test(address)) return false;
  if (noisySolanaPrograms.has(address)) return false;
  if (address.startsWith("Sysvar")) return false;
  return true;
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

function isRateLimitError(error: unknown): boolean {
  return error instanceof Error && /429|too many requests|rate/i.test(error.message);
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
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
  if (!data || data.length < 13 || data.readUInt32LE(0) !== 3) return {};
  const slot = data.readBigUInt64LE(4).toString();
  const option = data.readUInt8(12);
  if (option === 0) return { slot, upgradeAuthority: null };
  if (option === 1 && data.length >= 45) return { slot, upgradeAuthority: base58Encode(data.subarray(13, 45)) };
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

function deepDiscoveryFindings(metadata: SolanaProgramMetadata, discovery: SolanaDeepDiscovery): SecurityFinding[] {
  if (!metadata.fetched) return [];
  const discoveredCount = discovery.cpiPrograms.length + discovery.accounts.length;
  if (discovery.fetched && discoveredCount > 0) return [];

  const detail = discovery.error
    ? discovery.error
    : discovery.fetched
      ? `${discovery.signatureCount} signature(s) found, ${discovery.sampledTransactionCount} parsed transaction(s), 0 discovered CPI/account node(s)`
      : "Deep discovery did not run";

  return [
    {
      ruleId: "SOL-DEEPDISCOVERY-001",
      title: "Solana deep discovery did not expand recent program activity",
      description:
        "Packsight could not expand the program graph from sampled recent finalized transactions, so CPI programs and touched accounts may be missing.",
      severity: "info",
      confidence: "confirmed",
      status: "open",
      chainFamily: "solana",
      evidence: [{ type: "deep_discovery_limited", value: detail, source: discovery.error ? "scanner" : "onchain" }],
      affectedComponents: [metadata.programId],
      impact: "The program graph is limited to direct loader metadata, ProgramData and upgrade-authority relationships.",
      recommendation: "Retry with an archival/high-throughput Solana RPC endpoint or provide source/IDL plus transaction samples.",
      limitations: ["This is a coverage finding, not proof of exploitability."]
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
