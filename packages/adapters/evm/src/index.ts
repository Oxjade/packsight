import { access, readFile } from "node:fs/promises";
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

export interface EvmScanInput {
  network: string;
  contractAddress: string;
  repositoryUrl?: string;
  commitSha?: string;
  sourcePath?: string;
  customRpcUrl?: string;
}

export interface EvmScanArtifacts {
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
    blockNumber?: string;
    rpcUrl?: string;
  };
}

interface EvmContractMetadata {
  address: string;
  chainId?: string;
  blockNumber?: string;
  bytecode?: string;
  implementationAddress?: string;
  adminAddress?: string;
  beaconAddress?: string;
  abi?: EvmAbiItem[];
  abiSource?: string;
  endpoint?: string;
  fetched: boolean;
  error?: string;
}

interface EvmAbiItem {
  type?: string;
  name?: string;
  inputs?: Array<{ type?: string; name?: string }>;
  stateMutability?: string;
  constant?: boolean;
}

const evmAddress = /^0x[a-fA-F0-9]{40}$/;

const defaultRpcEndpoints: Record<string, string | undefined> = {
  mainnet: process.env.ETHEREUM_MAINNET_RPC_URL ?? process.env.EVM_MAINNET_RPC_URL ?? "https://cloudflare-eth.com",
  ethereum: process.env.ETHEREUM_MAINNET_RPC_URL ?? process.env.EVM_MAINNET_RPC_URL ?? "https://cloudflare-eth.com",
  sepolia: process.env.SEPOLIA_RPC_URL,
  holesky: process.env.HOLESKY_RPC_URL,
  polygon: process.env.POLYGON_RPC_URL,
  arbitrum: process.env.ARBITRUM_RPC_URL,
  optimism: process.env.OPTIMISM_RPC_URL,
  base: process.env.BASE_RPC_URL,
  bsc: process.env.BSC_RPC_URL
};

const etherscanChainIds: Record<string, string> = {
  mainnet: "1",
  ethereum: "1",
  sepolia: "11155111",
  holesky: "17000",
  polygon: "137",
  arbitrum: "42161",
  optimism: "10",
  base: "8453",
  bsc: "56"
};

const eip1967ImplementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const eip1967AdminSlot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const eip1967BeaconSlot = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

export async function scanEvmContract(input: EvmScanInput): Promise<EvmScanArtifacts> {
  const address = input.contractAddress.trim().toLowerCase();
  if (!evmAddress.test(address)) {
    throw new Error("Invalid EVM contract address. Expected a 0x-prefixed 20-byte address.");
  }

  const target: ScanTarget = {
    chainFamily: "evm",
    network: input.network,
    address,
    ...(input.repositoryUrl ? { repositoryUrl: input.repositoryUrl } : {}),
    ...(input.commitSha ? { commitSha: input.commitSha } : {})
  };

  const sourceAvailable = input.sourcePath ? await exists(input.sourcePath) : false;
  const sourceAbi = sourceAvailable ? await readLocalAbi(input.sourcePath as string) : undefined;
  const metadata = await fetchEvmContractMetadata({
    network: input.network,
    address,
    ...(sourceAbi ? { sourceAbi } : {}),
    ...(input.customRpcUrl ? { customRpcUrl: input.customRpcUrl } : {})
  });
  const abi = metadata.abi ?? sourceAbi ?? [];
  const findings = [...metadataFindings(metadata), ...sourceFindings(metadata, sourceAvailable), ...proxyFindings(metadata)];
  const currentVersion: CodeVersion = {
    identifier: metadata.blockNumber ? `block:${metadata.blockNumber}` : address,
    address,
    verified: Boolean(metadata.abi),
    activeStatus: "active"
  };

  return {
    target,
    versions: [currentVersion],
    callableSurface: abi.length > 0 ? abiCallableSurface(address, abi) : fallbackCallableSurface(address),
    versionFunctionDiffs: [],
    packageLinks: [],
    runtimeChecks: [],
    dependencies: [],
    findings,
    dataCoverage: {
      onchainMetadata: metadata.fetched ? "partial" : "unavailable",
      sourceCode: metadata.abi ? "partial" : sourceAvailable ? "partial" : "unavailable",
      historicalVersions: "unavailable",
      interfaceData: abi.length > 0 ? "complete" : "unavailable",
      dependencyGraph: "unavailable",
      runtimeReachability: "not_tested"
    },
    evidence: [
      {
        type: metadata.fetched ? "rpc_response" : "missing_information",
        value: metadata.fetched
          ? `Fetched EVM contract metadata for ${address}`
          : `Could not fetch EVM contract metadata: ${metadata.error ?? "unknown error"}`,
        source: "onchain"
      },
      ...(metadata.abiSource
        ? [
            {
              type: "abi_source",
              value: metadata.abiSource,
              source: metadata.abiSource === "local" ? ("repository" as const) : ("interface" as const)
            }
          ]
        : [])
    ],
    scanPoint: {
      ...(metadata.blockNumber ? { blockNumber: metadata.blockNumber } : {}),
      ...(metadata.endpoint ? { rpcUrl: metadata.endpoint } : {})
    }
  };
}

export function resolveEvmRpcUrl(network: string, customRpcUrl?: string): string {
  if (customRpcUrl) return customRpcUrl;
  if (network.startsWith("http")) return network;
  return defaultRpcEndpoints[network] ?? network;
}

async function fetchEvmContractMetadata(input: {
  network: string;
  address: string;
  sourceAbi?: EvmAbiItem[];
  customRpcUrl?: string;
}): Promise<EvmContractMetadata> {
  const endpoint = resolveEvmRpcUrl(input.network, input.customRpcUrl);
  if (!endpoint?.startsWith("http")) {
    return emptyMetadata(input.address, "No RPC endpoint configured for custom EVM network", endpoint);
  }

  try {
    const [chainId, blockNumber, bytecode, implementationSlot, adminSlot, beaconSlot] = await Promise.all([
      evmRpc<string>(endpoint, "eth_chainId", []),
      evmRpc<string>(endpoint, "eth_blockNumber", []),
      evmRpc<string>(endpoint, "eth_getCode", [input.address, "latest"]),
      evmRpc<string>(endpoint, "eth_getStorageAt", [input.address, eip1967ImplementationSlot, "latest"]),
      evmRpc<string>(endpoint, "eth_getStorageAt", [input.address, eip1967AdminSlot, "latest"]),
      evmRpc<string>(endpoint, "eth_getStorageAt", [input.address, eip1967BeaconSlot, "latest"])
    ]);
    const explorerAbi = input.sourceAbi ? undefined : await fetchExplorerAbi(input.network, input.address);
    const implementationAddress = storageAddress(implementationSlot);
    const adminAddress = storageAddress(adminSlot);
    const beaconAddress = storageAddress(beaconSlot);
    const metadata: EvmContractMetadata = {
      address: input.address,
      bytecode,
      ...(implementationAddress ? { implementationAddress } : {}),
      ...(adminAddress ? { adminAddress } : {}),
      ...(beaconAddress ? { beaconAddress } : {}),
      ...(input.sourceAbi ? { abi: input.sourceAbi, abiSource: "local" } : {}),
      ...(explorerAbi ? { abi: explorerAbi, abiSource: "explorer" } : {}),
      endpoint,
      fetched: true
    };
    const resolvedChainId = decimalHex(chainId);
    const resolvedBlockNumber = decimalHex(blockNumber);
    if (resolvedChainId) metadata.chainId = resolvedChainId;
    if (resolvedBlockNumber) metadata.blockNumber = resolvedBlockNumber;
    return metadata;
  } catch (error) {
    return emptyMetadata(input.address, error instanceof Error ? error.message : "unknown fetch error", endpoint);
  }
}

async function evmRpc<T>(endpoint: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: `packsight-${Date.now()}`, method, params })
  });
  if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
  const payload = (await response.json()) as { result?: T; error?: { message?: string } };
  if (payload.error) throw new Error(payload.error.message ?? "EVM RPC error");
  return payload.result as T;
}

async function fetchExplorerAbi(network: string, address: string): Promise<EvmAbiItem[] | undefined> {
  const apiKey = process.env.ETHERSCAN_API_KEY;
  const chainId = etherscanChainIds[network];
  if (!apiKey || !chainId) return undefined;
  const url = new URL("https://api.etherscan.io/v2/api");
  url.searchParams.set("chainid", chainId);
  url.searchParams.set("module", "contract");
  url.searchParams.set("action", "getabi");
  url.searchParams.set("address", address);
  url.searchParams.set("apikey", apiKey);
  const response = await fetch(url);
  if (!response.ok) return undefined;
  const payload = (await response.json()) as { status?: string; result?: string };
  if (payload.status !== "1" || !payload.result) return undefined;
  return JSON.parse(payload.result) as EvmAbiItem[];
}

async function readLocalAbi(sourcePath: string): Promise<EvmAbiItem[] | undefined> {
  const candidates = [join(sourcePath, "abi.json"), join(sourcePath, "out", "abi.json")];
  for (const candidate of candidates) {
    if (!(await exists(candidate))) continue;
    const parsed = JSON.parse(await readFile(candidate, "utf8")) as EvmAbiItem[] | { abi?: EvmAbiItem[] };
    return Array.isArray(parsed) ? parsed : parsed.abi;
  }
  return undefined;
}

function abiCallableSurface(address: string, abi: EvmAbiItem[]): CallableSurface[] {
  return abi
    .filter((item) => item.type === "function" && item.name)
    .map((item): CallableSurface => {
      const mutability = item.stateMutability ?? (item.constant ? "view" : "nonpayable");
      const signature = `${item.name as string}(${(item.inputs ?? []).map((input) => input.type ?? "unknown").join(",")})`;
      return {
        name: signature,
        module: "contract",
        address,
        visibility: mutability,
        deprecated: "unknown",
        reachable: "unknown",
        mutatesState: mutability === "view" || mutability === "pure" ? false : "unknown",
        valueSensitive: isSensitiveFunctionName(item.name as string)
      };
    });
}

function fallbackCallableSurface(address: string): CallableSurface[] {
  return [
    {
      name: `${address}::*`,
      module: "contract",
      address,
      visibility: "abi_unavailable",
      deprecated: "unknown",
      reachable: "unknown",
      mutatesState: "unknown",
      valueSensitive: "unknown"
    }
  ];
}

function metadataFindings(metadata: EvmContractMetadata): SecurityFinding[] {
  if (!metadata.fetched) {
    return [
      {
        ruleId: "EVM-METADATA-001",
        title: "EVM contract metadata could not be fetched",
        description: "Packsight could not fetch bytecode or storage metadata from the configured EVM RPC endpoint.",
        severity: "info",
        confidence: "confirmed",
        status: "open",
        chainFamily: "evm",
        evidence: [{ type: "missing_information", value: metadata.error ?? "EVM RPC metadata unavailable" }],
        affectedComponents: [metadata.address],
        impact: "Bytecode, proxy, and interface coverage are unavailable.",
        recommendation: "Retry with a reachable EVM RPC endpoint or provide a custom RPC URL.",
        limitations: ["This is a coverage finding, not proof of exploitability."]
      }
    ];
  }

  if (!metadata.bytecode || metadata.bytecode === "0x") {
    return [
      {
        ruleId: "EVM-BYTECODE-001",
        title: "Address has no deployed EVM bytecode",
        description: "The scanned address returned empty bytecode at the scan block.",
        severity: "info",
        confidence: "confirmed",
        status: "open",
        chainFamily: "evm",
        evidence: [{ type: "bytecode", value: "0x", source: "onchain" }],
        affectedComponents: [metadata.address],
        impact: "The target appears to be an EOA or an address without code on this network.",
        recommendation: "Confirm the network and contract address.",
        limitations: ["Historical code at prior blocks was not queried."]
      }
    ];
  }

  return [];
}

function sourceFindings(metadata: EvmContractMetadata, sourceAvailable: boolean): SecurityFinding[] {
  if (metadata.abi) return [];
  return [
    {
      ruleId: "EVM-SOURCE-001",
      title: "EVM ABI or verified source is unavailable",
      description: "No ABI was found from local source or explorer metadata, so packsight cannot enumerate contract functions.",
      severity: "info",
      confidence: "confirmed",
      status: "open",
      chainFamily: "evm",
      evidence: [{ type: "missing_information", value: sourceAvailable ? "abi.json unavailable" : "sourcePath and explorer ABI unavailable" }],
      affectedComponents: [metadata.address],
      impact: "Callable function coverage is limited to a wildcard contract surface.",
      recommendation: "Provide abi.json, verified source, or configure ETHERSCAN_API_KEY for explorer ABI lookups.",
      limitations: ["Bytecode-only function recovery is not implemented in this MVP."]
    }
  ];
}

function proxyFindings(metadata: EvmContractMetadata): SecurityFinding[] {
  if (!metadata.implementationAddress && !metadata.beaconAddress) return [];
  return [
    {
      ruleId: "EVM-PROXY-001",
      title: "EIP-1967 proxy storage slot is populated",
      description: "The contract has EIP-1967 implementation or beacon storage populated, indicating proxy-style upgradeability.",
      severity: "medium",
      confidence: "high",
      status: "open",
      chainFamily: "evm",
      evidence: [
        ...(metadata.implementationAddress
          ? [{ type: "implementation_address", value: metadata.implementationAddress, source: "onchain" as const }]
          : []),
        ...(metadata.beaconAddress ? [{ type: "beacon_address", value: metadata.beaconAddress, source: "onchain" as const }] : []),
        ...(metadata.adminAddress ? [{ type: "admin_address", value: metadata.adminAddress, source: "onchain" as const }] : [])
      ],
      affectedComponents: [metadata.address],
      impact: "The contract logic may be upgradeable, so auditors should inspect proxy admin controls and implementation history.",
      recommendation: "Review proxy admin ownership, timelocks, upgrade events, and the implementation contract source.",
      limitations: ["The scanner does not prove the proxy admin is malicious or unsafe."]
    }
  ];
}

function storageAddress(value: string | undefined): string | undefined {
  if (!value || value === "0x" || /^0x0+$/.test(value)) return undefined;
  const normalized = value.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  const address = `0x${normalized.slice(-40)}`;
  return /^0x0+$/.test(address) ? undefined : address;
}

function decimalHex(hex: string | undefined): string | undefined {
  if (!hex) return undefined;
  return BigInt(hex).toString();
}

function isSensitiveFunctionName(name: string): boolean | "unknown" {
  return /\b(withdraw|admin|owner|upgrade|mint|burn|transfer|claim|vault|fee|sweep|pause|delegate)\b/i.test(
    name.replace(/_/g, " ")
  )
    ? true
    : "unknown";
}

function emptyMetadata(address: string, error: string, endpoint?: string): EvmContractMetadata {
  return {
    address,
    ...(endpoint ? { endpoint } : {}),
    fetched: false,
    error
  };
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
