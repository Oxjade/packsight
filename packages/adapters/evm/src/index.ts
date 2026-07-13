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
  chainId?: string;
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
    chainId?: string;
    rpcUrl?: string;
  };
}

interface EvmContractMetadata {
  address: string;
  chainId?: string;
  blockNumber?: string;
  deploymentBlockNumber?: string;
  creationTxHash?: string;
  creatorAddress?: string;
  bytecode?: string;
  implementationAddress?: string;
  adminAddress?: string;
  beaconAddress?: string;
  abi?: EvmAbiItem[];
  abiSource?: string;
  endpoint?: string;
  fetched: boolean;
  error?: string;
  expectedChainId?: string;
  chainIdMismatch?: boolean;
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
  monad: process.env.MONAD_RPC_URL ?? process.env.MONAD_MAINNET_RPC_URL ?? "https://rpc.monad.xyz",
  "monad-mainnet": process.env.MONAD_RPC_URL ?? process.env.MONAD_MAINNET_RPC_URL ?? "https://rpc.monad.xyz",
  monad_mainnet: process.env.MONAD_RPC_URL ?? process.env.MONAD_MAINNET_RPC_URL ?? "https://rpc.monad.xyz",
  sepolia: process.env.SEPOLIA_RPC_URL,
  holesky: process.env.HOLESKY_RPC_URL,
  polygon: process.env.POLYGON_RPC_URL,
  arbitrum: process.env.ARBITRUM_RPC_URL,
  optimism: process.env.OPTIMISM_RPC_URL,
  base: process.env.BASE_RPC_URL,
  bsc: process.env.BSC_RPC_URL
};

const defaultRpcEndpointsByChainId: Record<string, string | undefined> = {
  "1": defaultRpcEndpoints.mainnet,
  "10": defaultRpcEndpoints.optimism,
  "56": defaultRpcEndpoints.bsc,
  "137": defaultRpcEndpoints.polygon,
  "143": defaultRpcEndpoints.monad,
  "8453": defaultRpcEndpoints.base,
  "17000": defaultRpcEndpoints.holesky,
  "42161": defaultRpcEndpoints.arbitrum,
  "11155111": defaultRpcEndpoints.sepolia
};

const etherscanChainIds: Record<string, string> = {
  mainnet: "1",
  ethereum: "1",
  monad: "143",
  "monad-mainnet": "143",
  monad_mainnet: "143",
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
    ...(input.chainId ? { chainId: input.chainId } : {}),
    address,
    ...(input.repositoryUrl ? { repositoryUrl: input.repositoryUrl } : {}),
    ...(input.commitSha ? { commitSha: input.commitSha } : {})
  };

  const sourceAvailable = input.sourcePath ? await exists(input.sourcePath) : false;
  const sourceAbi = sourceAvailable ? await readLocalAbi(input.sourcePath as string) : undefined;
  const metadata = await fetchEvmContractMetadata({
    network: input.network,
    address,
    ...(input.chainId ? { expectedChainId: input.chainId } : {}),
    ...(sourceAbi ? { sourceAbi } : {}),
    ...(input.customRpcUrl ? { customRpcUrl: input.customRpcUrl } : {})
  });
  const abi = metadata.abi ?? sourceAbi ?? [];
  const findings = [...metadataFindings(metadata), ...sourceFindings(metadata, sourceAvailable), ...proxyFindings(metadata)];
  const currentVersion: CodeVersion = {
    identifier: metadata.deploymentBlockNumber
      ? `deployment:${metadata.deploymentBlockNumber}`
      : metadata.blockNumber
        ? `block:${metadata.blockNumber}`
        : address,
    address,
    verified: Boolean(metadata.abi),
    activeStatus: "active"
  };
  const contractLinks = evmContractLinks(metadata);
  const relatedVersions = evmRelatedVersions(metadata);

  return {
    target,
    versions: [currentVersion, ...relatedVersions],
    callableSurface: abi.length > 0 ? abiCallableSurface(address, abi) : fallbackCallableSurface(address),
    versionFunctionDiffs: [],
    packageLinks: contractLinks,
    runtimeChecks: [],
    dependencies: [],
    findings,
    dataCoverage: {
      onchainMetadata: metadata.fetched ? "partial" : "unavailable",
      sourceCode: metadata.abi ? "partial" : sourceAvailable ? "partial" : "unavailable",
      historicalVersions: relatedVersions.length > 0 || metadata.deploymentBlockNumber ? "partial" : "unavailable",
      interfaceData: abi.length > 0 ? "complete" : "unavailable",
      dependencyGraph: contractLinks.length > 0 ? "partial" : "unavailable",
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
        : []),
      ...(metadata.creationTxHash
        ? [
            {
              type: "contract_creation",
              value: [
                `tx=${metadata.creationTxHash}`,
                ...(metadata.deploymentBlockNumber ? [`block=${metadata.deploymentBlockNumber}`] : []),
                ...(metadata.creatorAddress ? [`creator=${metadata.creatorAddress}`] : [])
              ].join(" "),
              source: "interface" as const
            }
          ]
        : [])
    ],
    scanPoint: {
      ...(metadata.blockNumber ? { blockNumber: metadata.blockNumber } : {}),
      ...(metadata.chainId ? { chainId: metadata.chainId } : input.chainId ? { chainId: input.chainId } : {}),
      ...(metadata.endpoint ? { rpcUrl: metadata.endpoint } : {})
    }
  };
}

function evmContractLinks(metadata: EvmContractMetadata): PackageLink[] {
  if (!metadata.fetched) return [];
  const links: PackageLink[] = [];
  const sourcePackageVersion = metadata.deploymentBlockNumber
    ? `deployment:${metadata.deploymentBlockNumber}`
    : metadata.blockNumber
      ? `block:${metadata.blockNumber}`
      : undefined;

  if (metadata.creatorAddress) {
    links.push(
      evmContractLink(metadata.address, metadata.creatorAddress, "contract_creator", sourcePackageVersion, [
        ...(metadata.creationTxHash ? [{ type: "creation_tx", value: metadata.creationTxHash, source: "interface" as const }] : []),
        ...(metadata.deploymentBlockNumber
          ? [{ type: "deployment_block", value: metadata.deploymentBlockNumber, source: "onchain" as const }]
          : [])
      ])
    );
  }

  if (metadata.implementationAddress) {
    links.push(evmContractLink(metadata.address, metadata.implementationAddress, "proxy_implementation", sourcePackageVersion));
  }

  if (metadata.beaconAddress) {
    links.push(evmContractLink(metadata.address, metadata.beaconAddress, "proxy_beacon", sourcePackageVersion));
  }

  if (metadata.adminAddress) {
    links.push(evmContractLink(metadata.address, metadata.adminAddress, "proxy_admin", sourcePackageVersion));
  }

  return links;
}

function evmContractLink(
  sourceAddress: string,
  resolvedAddress: string,
  relationship: string,
  sourcePackageVersion?: string,
  extraEvidence: Evidence[] = []
): PackageLink {
  return {
    sourcePackageAddress: sourceAddress,
    ...(sourcePackageVersion ? { sourcePackageVersion } : {}),
    originalPackageId: sourceAddress,
    resolvedPackageId: resolvedAddress,
    status: "unchanged",
    relationship,
    evidence: [{ type: relationship, value: resolvedAddress, source: "onchain" }, ...extraEvidence]
  };
}

function evmRelatedVersions(metadata: EvmContractMetadata): CodeVersion[] {
  const versions: CodeVersion[] = [];

  if (metadata.implementationAddress) {
    versions.push({
      identifier: `implementation:${metadata.implementationAddress}`,
      address: metadata.implementationAddress,
      verified: false,
      activeStatus: "unknown"
    });
  }

  if (metadata.beaconAddress) {
    versions.push({
      identifier: `beacon:${metadata.beaconAddress}`,
      address: metadata.beaconAddress,
      verified: false,
      activeStatus: "unknown"
    });
  }

  return versions;
}

export function resolveEvmRpcUrl(network: string, chainId?: string, customRpcUrl?: string): string {
  if (customRpcUrl) return customRpcUrl;
  if (network.startsWith("http")) return network;
  const normalizedNetwork = network.toLowerCase();
  return defaultRpcEndpoints[normalizedNetwork] ?? (chainId ? defaultRpcEndpointsByChainId[chainId] : undefined) ?? network;
}

async function fetchEvmContractMetadata(input: {
  network: string;
  address: string;
  expectedChainId?: string;
  sourceAbi?: EvmAbiItem[];
  customRpcUrl?: string;
}): Promise<EvmContractMetadata> {
  const endpoint = resolveEvmRpcUrl(input.network, input.expectedChainId, input.customRpcUrl);
  if (!endpoint?.startsWith("http")) {
    return emptyMetadata(input.address, "No RPC endpoint configured for custom EVM network", endpoint, input.expectedChainId);
  }

  try {
    const [chainId, blockNumber, bytecode] = await Promise.all([
      evmRpc<string>(endpoint, "eth_chainId", []),
      evmRpc<string>(endpoint, "eth_blockNumber", []),
      evmRpc<string>(endpoint, "eth_getCode", [input.address, "latest"])
    ]);
    const [implementationSlot, adminSlot, beaconSlot] = await Promise.all([
      safeEvmRpc<string>(endpoint, "eth_getStorageAt", [input.address, eip1967ImplementationSlot, "latest"]),
      safeEvmRpc<string>(endpoint, "eth_getStorageAt", [input.address, eip1967AdminSlot, "latest"]),
      safeEvmRpc<string>(endpoint, "eth_getStorageAt", [input.address, eip1967BeaconSlot, "latest"])
    ]);
    const resolvedChainId = decimalHex(chainId);
    const explorerAbi = input.sourceAbi ? undefined : await fetchExplorerAbi(input.network, input.address, input.expectedChainId);
    const deploymentChainId = input.expectedChainId ?? resolvedChainId;
    const deployment = await fetchDeploymentMetadata({
      endpoint,
      network: input.network,
      address: input.address,
      ...(deploymentChainId ? { chainId: deploymentChainId } : {})
    });
    const implementationAddress = storageAddress(implementationSlot);
    const adminAddress = storageAddress(adminSlot);
    const beaconAddress = storageAddress(beaconSlot);
    const metadata: EvmContractMetadata = {
      address: input.address,
      bytecode,
      ...(implementationAddress ? { implementationAddress } : {}),
      ...(adminAddress ? { adminAddress } : {}),
      ...(beaconAddress ? { beaconAddress } : {}),
      ...(deployment?.blockNumber ? { deploymentBlockNumber: deployment.blockNumber } : {}),
      ...(deployment?.txHash ? { creationTxHash: deployment.txHash } : {}),
      ...(deployment?.creatorAddress ? { creatorAddress: deployment.creatorAddress } : {}),
      ...(input.sourceAbi ? { abi: input.sourceAbi, abiSource: "local" } : {}),
      ...(explorerAbi ? { abi: explorerAbi, abiSource: "explorer" } : {}),
      endpoint,
      fetched: true,
      ...(input.expectedChainId ? { expectedChainId: input.expectedChainId } : {})
    };
    const resolvedBlockNumber = decimalHex(blockNumber);
    if (resolvedChainId) metadata.chainId = resolvedChainId;
    if (input.expectedChainId && resolvedChainId && input.expectedChainId !== resolvedChainId) {
      metadata.chainIdMismatch = true;
    }
    if (resolvedBlockNumber) metadata.blockNumber = resolvedBlockNumber;
    return metadata;
  } catch (error) {
    return emptyMetadata(
      input.address,
      error instanceof Error ? error.message : "unknown fetch error",
      endpoint,
      input.expectedChainId
    );
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

async function safeEvmRpc<T>(endpoint: string, method: string, params: unknown[]): Promise<T | undefined> {
  try {
    return await evmRpc<T>(endpoint, method, params);
  } catch {
    return undefined;
  }
}

async function fetchExplorerAbi(network: string, address: string, providedChainId?: string): Promise<EvmAbiItem[] | undefined> {
  const apiKey = process.env.ETHERSCAN_API_KEY;
  const chainId = providedChainId ?? etherscanChainIds[network];
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

interface EvmDeploymentMetadata {
  blockNumber?: string;
  creatorAddress?: string;
  txHash?: string;
}

async function fetchDeploymentMetadata(input: {
  endpoint: string;
  network: string;
  address: string;
  chainId?: string;
}): Promise<EvmDeploymentMetadata | undefined> {
  const explorerCreation = await fetchExplorerContractCreation(input.network, input.address, input.chainId);
  const monadScanCreation =
    explorerCreation?.txHash || input.chainId !== "143" ? undefined : await fetchMonadScanContractCreation(input.address);
  const creation = explorerCreation ?? monadScanCreation;
  if (!creation?.txHash) return creation;

  const receipt = await safeEvmRpc<{
    blockNumber?: string;
    contractAddress?: string | null;
  }>(input.endpoint, "eth_getTransactionReceipt", [creation.txHash]);
  const deployedAddress = receipt?.contractAddress?.toLowerCase();
  if (deployedAddress && deployedAddress !== input.address.toLowerCase()) return creation;

  const blockNumber = receipt?.blockNumber ? decimalHex(receipt.blockNumber) : undefined;
  return {
    ...creation,
    ...(blockNumber ? { blockNumber } : {})
  };
}

async function fetchExplorerContractCreation(
  network: string,
  address: string,
  providedChainId?: string
): Promise<EvmDeploymentMetadata | undefined> {
  const apiKey = process.env.ETHERSCAN_API_KEY;
  const chainId = providedChainId ?? etherscanChainIds[network];
  if (!apiKey || !chainId) return undefined;
  const url = new URL("https://api.etherscan.io/v2/api");
  url.searchParams.set("chainid", chainId);
  url.searchParams.set("module", "contract");
  url.searchParams.set("action", "getcontractcreation");
  url.searchParams.set("contractaddresses", address);
  url.searchParams.set("apikey", apiKey);
  const response = await fetch(url);
  if (!response.ok) return undefined;
  const payload = (await response.json()) as {
    status?: string;
    result?: Array<{ contractCreator?: string; txHash?: string; contractAddress?: string }>;
  };
  const result = payload.status === "1" ? payload.result?.[0] : undefined;
  if (!result?.txHash) return undefined;
  return {
    txHash: result.txHash.toLowerCase(),
    ...(result.contractCreator ? { creatorAddress: result.contractCreator.toLowerCase() } : {})
  };
}

async function fetchMonadScanContractCreation(address: string): Promise<EvmDeploymentMetadata | undefined> {
  try {
    const response = await fetch(`https://monadscan.com/address/${address}`);
    if (!response.ok) return undefined;
    const html = await response.text();
    const contractSection = html.match(/<div id="ContentPlaceHolder1_trContract">[\s\S]*?<!-- End Contract Creator -->/)?.[0];
    if (!contractSection) return undefined;
    const creatorAddress = contractSection.match(/Creator Address \((0x[a-fA-F0-9]{40})\)/)?.[1]?.toLowerCase();
    const txHash = contractSection.match(/href="\/tx\/(0x[a-fA-F0-9]{64})"/)?.[1]?.toLowerCase();
    if (!creatorAddress && !txHash) return undefined;
    return {
      ...(creatorAddress ? { creatorAddress } : {}),
      ...(txHash ? { txHash } : {})
    };
  } catch {
    return undefined;
  }
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

  if (metadata.chainIdMismatch) {
    return [
      {
        ruleId: "EVM-CHAINID-001",
        title: "Declared EVM chain ID does not match RPC chain ID",
        description: `The scan request declared chain ID ${metadata.expectedChainId}, but the configured RPC returned chain ID ${metadata.chainId}.`,
        severity: "high",
        confidence: "confirmed",
        status: "open",
        chainFamily: "evm",
        evidence: [
          ...(metadata.expectedChainId
            ? [{ type: "declared_chain_id", value: metadata.expectedChainId, source: "scanner" as const }]
            : []),
          ...(metadata.chainId ? [{ type: "rpc_chain_id", value: metadata.chainId, source: "onchain" as const }] : [])
        ],
        affectedComponents: [metadata.address],
        impact: "The report may be describing a contract on a different EVM chain than the user intended.",
        recommendation: "Correct the chain ID or RPC endpoint, then rerun the scan before acting on findings.",
        limitations: ["This finding indicates target selection risk, not a contract exploit."]
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

function emptyMetadata(address: string, error: string, endpoint?: string, expectedChainId?: string): EvmContractMetadata {
  return {
    address,
    ...(endpoint ? { endpoint } : {}),
    ...(expectedChainId ? { expectedChainId } : {}),
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
