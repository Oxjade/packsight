import { access } from "node:fs/promises";
import { analyzeMoveSource } from "@packsight/move-analyzer";
import { scanMoveDependencies } from "@packsight/dependency-scanner";
import type {
  CallableSurface,
  CodeVersion,
  CoverageState,
  DataCoverage,
  DependencyRecord,
  Evidence,
  PackageLink,
  RuntimeCheck,
  ScanTarget,
  SecurityFinding,
  VersionFunctionDiff
} from "@packsight/report-schema";
import { evaluateSuiSourceRules } from "@packsight/rule-engine";

export interface SuiScanInput {
  network: string;
  packageId: string;
  repositoryUrl?: string;
  commitSha?: string;
  sourcePath?: string;
  customGraphqlUrl?: string;
}

export interface SuiScanArtifacts {
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
    chainCheckpoint?: string;
    rpcUrl?: string;
  };
}

interface SuiPackageMetadata {
  packageId: string;
  version?: string;
  digest?: string;
  previousTransactionDigest?: string;
  moduleNames: string[];
  functions: SuiMoveFunction[];
  linkage: SuiLinkage[];
  previousVersions: SuiPackageVersion[];
  laterVersions: SuiPackageVersion[];
  hasMorePreviousVersions: boolean;
  hasMoreLaterVersions: boolean;
  checkpoint?: string;
  endpoint?: string;
  fetched: boolean;
  error?: string;
}

interface SuiMoveFunction {
  moduleName: string;
  name: string;
  fullyQualifiedName: string;
  isEntry: boolean;
  visibility: string;
  parameters: string[];
  returns: string[];
}

interface SuiPackageVersion {
  address: string;
  version: string;
  digest?: string;
}

interface SuiLinkage {
  originalId: string;
  upgradedId: string;
  version: string;
}

const suiPackageId = /^0x[a-fA-F0-9]{1,64}$/;

const defaultGraphqlEndpoints: Record<string, string> = {
  mainnet: process.env.SUI_MAINNET_GRAPHQL_URL ?? "https://graphql.mainnet.sui.io/graphql",
  testnet: process.env.SUI_TESTNET_GRAPHQL_URL ?? "https://graphql.testnet.sui.io/graphql",
  devnet: process.env.SUI_DEVNET_GRAPHQL_URL ?? "https://graphql.devnet.sui.io/graphql"
};

export async function scanSuiPackage(input: SuiScanInput): Promise<SuiScanArtifacts> {
  const packageId = normalizePackageId(input.packageId);
  if (!suiPackageId.test(packageId)) {
    throw new Error("Invalid Sui package ID. Expected a 0x-prefixed hexadecimal object ID.");
  }

  const target: ScanTarget = {
    chainFamily: "sui",
    network: input.network,
    address: packageId,
    ...(input.repositoryUrl ? { repositoryUrl: input.repositoryUrl } : {}),
    ...(input.commitSha ? { commitSha: input.commitSha } : {})
  };

  const metadataInput: {
    network: string;
    packageId: string;
    customGraphqlUrl?: string;
  } = {
    network: input.network,
    packageId
  };
  if (input.customGraphqlUrl) {
    metadataInput.customGraphqlUrl = input.customGraphqlUrl;
  }
  const metadata = await fetchSuiPackageMetadata(metadataInput);
  const latestVersion = metadata.laterVersions.at(-1);
  const latestMetadata =
    latestVersion && latestVersion.address !== packageId
      ? await fetchSuiPackageMetadata({
          network: input.network,
          packageId: latestVersion.address,
          ...(input.customGraphqlUrl ? { customGraphqlUrl: input.customGraphqlUrl } : {})
        })
      : undefined;
  const previousVersionMetadata =
    metadata.fetched && metadata.laterVersions.length === 0
      ? await fetchComparablePreviousVersions({
          metadata,
          network: input.network,
          ...(input.customGraphqlUrl ? { customGraphqlUrl: input.customGraphqlUrl } : {})
        })
      : [];

  const sourceAvailable = input.sourcePath ? await exists(input.sourcePath) : false;
  const sourceAnalysis = sourceAvailable
    ? await analyzeMoveSource(input.sourcePath as string)
    : {
        callableSurface: [],
        functions: [],
        evidence: [{ type: "missing_information" as const, value: "No sourcePath supplied" }],
        sourceFiles: [],
        oldPackageReferences: [],
        hasVersionState: false
      };

  const dependencyResult = sourceAvailable
    ? await scanMoveDependencies(input.sourcePath as string)
    : { dependencies: [], findings: [], evidence: [], lockfilePresent: false };

  const findings = [
    ...evaluateSuiSourceRules(sourceAnalysis),
    ...dependencyResult.findings,
    ...versionFindings(metadata),
    ...previousVersionFindings(metadata, previousVersionMetadata),
    ...versionFunctionDiffFindings(metadata, latestMetadata),
    ...previousVersionMetadata.flatMap((legacyMetadata) => versionFunctionDiffFindings(legacyMetadata, metadata)),
    ...packageLinkFindings(metadata, latestMetadata),
    ...previousVersionMetadata.flatMap((legacyMetadata) => packageLinkFindings(legacyMetadata, metadata)),
    ...metadataFindings(metadata)
  ];
  const runtimeChecks = [
    ...buildRuntimeChecks(metadata, sourceAnalysis.functions, sourceAvailable),
    ...previousVersionMetadata.flatMap((legacyMetadata) => buildRuntimeChecks(legacyMetadata, [], false))
  ];

  const onchainCallableSurface = [
    ...buildCallableSurface(metadata, sourceAnalysis.functions),
    ...previousVersionMetadata.flatMap((legacyMetadata) => buildCallableSurface(legacyMetadata, []))
  ];

  const dependencies = [
    ...dependencyResult.dependencies,
    ...metadata.linkage.map((link): DependencyRecord => ({
      ecosystem: "move",
      name: link.originalId,
      resolvedVersion: link.version,
      source: `sui-linkage:${link.upgradedId}`,
      direct: true,
      deprecated: linkedPackageStatus(link, latestMetadata) === "upgraded_in_latest" ? true : false,
      yanked: "unknown",
      vulnerable: "unknown",
      advisories: []
    }))
  ];

  const currentVersion: CodeVersion = {
    identifier: metadata.version ?? packageId,
    ...(metadata.version ? { version: metadata.version } : {}),
    address: packageId,
    ...(metadata.previousTransactionDigest ? { transactionHash: metadata.previousTransactionDigest } : {}),
    verified: sourceAvailable,
    activeStatus: metadata.laterVersions.length > 0 ? "legacy" : "active"
  };

  const versions = [
    ...metadata.previousVersions.map((version): CodeVersion => ({
      identifier: version.version,
      version: version.version,
      address: version.address,
      ...(version.digest ? { transactionHash: version.digest } : {}),
      verified: false,
      activeStatus: "legacy"
    })),
    currentVersion,
    ...metadata.laterVersions.map((version, index, versionsAfter): CodeVersion => ({
      identifier: version.version,
      version: version.version,
      address: version.address,
      ...(version.digest ? { transactionHash: version.digest } : {}),
      verified: false,
      activeStatus: index === versionsAfter.length - 1 ? "active" : "legacy"
    }))
  ];

  return {
    target,
    versions,
    callableSurface:
      sourceAnalysis.callableSurface.length > 0 ? sourceAnalysis.callableSurface : onchainCallableSurface,
    versionFunctionDiffs: [
      ...buildVersionFunctionDiffs(metadata, latestMetadata),
      ...previousVersionMetadata.flatMap((legacyMetadata) => buildVersionFunctionDiffs(legacyMetadata, metadata))
    ],
    packageLinks: [
      ...buildPackageLinks(metadata, latestMetadata),
      ...previousVersionMetadata.flatMap((legacyMetadata) => buildPackageLinks(legacyMetadata, metadata))
    ],
    runtimeChecks,
    dependencies,
    findings,
    dataCoverage: coverageFor(metadata, sourceAvailable, dependencyResult.lockfilePresent),
    evidence: [
      ...sourceAnalysis.evidence,
      ...dependencyResult.evidence,
      {
        type: metadata.fetched ? "graphql_response" : "missing_information",
        value: metadata.fetched
          ? `Fetched Sui package metadata for ${packageId}`
          : `Could not fetch Sui package metadata: ${metadata.error ?? "unknown error"}`
      }
    ],
    scanPoint: {
      ...(metadata.checkpoint ? { chainCheckpoint: metadata.checkpoint } : {}),
      ...(metadata.endpoint ? { rpcUrl: metadata.endpoint } : {})
    }
  };
}

export function resolveSuiGraphqlUrl(network: string, customGraphqlUrl?: string): string {
  if (customGraphqlUrl) {
    return customGraphqlUrl;
  }
  return defaultGraphqlEndpoints[network] ?? network;
}

async function fetchComparablePreviousVersions(input: {
  metadata: SuiPackageMetadata;
  network: string;
  customGraphqlUrl?: string;
}): Promise<SuiPackageMetadata[]> {
  const previousVersions = input.metadata.previousVersions.filter((version) => version.address !== input.metadata.packageId);
  const results = await Promise.all(
    previousVersions.map((version) =>
      fetchSuiPackageMetadata({
        network: input.network,
        packageId: version.address,
        ...(input.customGraphqlUrl ? { customGraphqlUrl: input.customGraphqlUrl } : {})
      })
    )
  );

  return results.filter((metadata) => metadata.fetched);
}

async function fetchSuiPackageMetadata(input: {
  network: string;
  packageId: string;
  customGraphqlUrl?: string;
}): Promise<SuiPackageMetadata> {
  const endpoint = resolveSuiGraphqlUrl(input.network, input.customGraphqlUrl);
  if (!endpoint.startsWith("http")) {
    return emptyMetadata(input.packageId, "No GraphQL endpoint configured for custom network", endpoint);
  }

  const query = `
    query PacksightPackage($address: SuiAddress!) {
      object(address: $address) {
        address
        version
        digest
        previousTransaction {
          digest
        }
        asMovePackage {
          address
          version
          digest
          linkage {
            originalId
            upgradedId
            version
          }
          packageVersionsBefore(first: 10) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              address
              version
              digest
            }
          }
          packageVersionsAfter(first: 10) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              address
              version
              digest
            }
          }
          modules(first: 50) {
            nodes {
              name
              functions(first: 50) {
                nodes {
                  name
                  fullyQualifiedName
                  isEntry
                  visibility
                  parameters {
                    repr
                  }
                  return {
                    repr
                  }
                }
              }
            }
          }
        }
      }
      checkpoint {
        sequenceNumber
      }
    }
  `;

  try {
    const response = await fetchWithRetry(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sui-rpc-request-id": `packsight-${Date.now()}`
      },
      body: JSON.stringify({ query, variables: { address: input.packageId } })
    });

    if (!response.ok) {
      return emptyMetadata(input.packageId, `GraphQL HTTP ${response.status}`, endpoint);
    }

    const payload = (await response.json()) as {
      data?: {
        object?: {
          address?: string;
          version?: string;
          digest?: string;
          previousTransaction?: { digest?: string };
          asMovePackage?: {
            address?: string;
            version?: string | number;
            digest?: string;
            linkage?: Array<{ originalId?: string; upgradedId?: string; version?: string | number }>;
            packageVersionsBefore?: {
              pageInfo?: { hasNextPage?: boolean; endCursor?: string | null };
              nodes?: Array<{ address?: string; version?: string | number; digest?: string }>;
            };
            packageVersionsAfter?: {
              pageInfo?: { hasNextPage?: boolean; endCursor?: string | null };
              nodes?: Array<{ address?: string; version?: string | number; digest?: string }>;
            };
            modules?: {
              nodes?: Array<{
                name?: string;
                functions?: {
                  nodes?: Array<{
                    name?: string;
                    fullyQualifiedName?: string;
                    isEntry?: boolean;
                    visibility?: string;
                    parameters?: Array<{ repr?: string }>;
                    return?: Array<{ repr?: string }>;
                  }>;
                };
              }>;
            };
          };
        };
        checkpoint?: { sequenceNumber?: string };
      };
      errors?: Array<{ message?: string }>;
    };

    if (payload.errors?.length) {
      return emptyMetadata(
        input.packageId,
        payload.errors.map((error) => error.message ?? "GraphQL error").join("; "),
        endpoint
      );
    }

    const moduleNames =
      payload.data?.object?.asMovePackage?.modules?.nodes
        ?.map((node) => node.name)
        .filter((name): name is string => Boolean(name)) ?? [];
    const functions = extractGraphqlFunctions(payload.data?.object?.asMovePackage?.modules?.nodes ?? [], input.packageId);
    const previousPage = payload.data?.object?.asMovePackage?.packageVersionsBefore;
    const laterPage = payload.data?.object?.asMovePackage?.packageVersionsAfter;
    const previousVersionNodes = [
      ...(previousPage?.nodes ?? []),
      ...(await fetchRemainingPackageVersionPages({
        endpoint,
        packageId: input.packageId,
        direction: "before",
        ...(previousPage?.pageInfo?.endCursor ? { cursor: previousPage.pageInfo.endCursor } : {}),
        hasNextPage: Boolean(previousPage?.pageInfo?.hasNextPage)
      }))
    ];
    const laterVersionNodes = [
      ...(laterPage?.nodes ?? []),
      ...(await fetchRemainingPackageVersionPages({
        endpoint,
        packageId: input.packageId,
        direction: "after",
        ...(laterPage?.pageInfo?.endCursor ? { cursor: laterPage.pageInfo.endCursor } : {}),
        hasNextPage: Boolean(laterPage?.pageInfo?.hasNextPage)
      }))
    ];
    const linkage = (payload.data?.object?.asMovePackage?.linkage ?? [])
      .filter((link) => link.originalId && link.upgradedId && link.version !== undefined)
      .map((link) => ({
        originalId: normalizePackageId(link.originalId as string),
        upgradedId: normalizePackageId(link.upgradedId as string),
        version: String(link.version)
      }));

    const metadata: SuiPackageMetadata = {
      packageId: input.packageId,
      moduleNames,
      functions,
      linkage,
      previousVersions: normalizePackageVersions(previousVersionNodes),
      laterVersions: normalizePackageVersions(laterVersionNodes),
      hasMorePreviousVersions: false,
      hasMoreLaterVersions: false,
      endpoint,
      fetched: true
    };
    if (payload.data?.object?.version !== undefined) {
      metadata.version = String(payload.data.object.version);
    }
    if (payload.data?.object?.digest) {
      metadata.digest = payload.data.object.digest;
    }
    if (payload.data?.object?.previousTransaction?.digest) {
      metadata.previousTransactionDigest = payload.data.object.previousTransaction.digest;
    }
    if (payload.data?.checkpoint?.sequenceNumber) {
      metadata.checkpoint = String(payload.data.checkpoint.sequenceNumber);
    }
    return metadata;
  } catch (error) {
    return emptyMetadata(input.packageId, error instanceof Error ? error.message : "unknown fetch error", endpoint);
  }
}

async function fetchRemainingPackageVersionPages(input: {
  endpoint: string;
  packageId: string;
  direction: "before" | "after";
  cursor?: string;
  hasNextPage: boolean;
}): Promise<Array<{ address?: string; version?: string | number; digest?: string }>> {
  const nodes: Array<{ address?: string; version?: string | number; digest?: string }> = [];
  let cursor = input.cursor;
  let hasNextPage = input.hasNextPage;
  const fieldName = input.direction === "before" ? "packageVersionsBefore" : "packageVersionsAfter";

  while (hasNextPage && cursor) {
    const query = `
      query PacksightPackageVersions($address: SuiAddress!, $after: String) {
        object(address: $address) {
          asMovePackage {
            ${fieldName}(first: 50, after: $after) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                address
                version
                digest
              }
            }
          }
        }
      }
    `;

    const response = await fetchWithRetry(input.endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sui-rpc-request-id": `packsight-${Date.now()}`
      },
      body: JSON.stringify({ query, variables: { address: input.packageId, after: cursor } })
    });

    if (!response.ok) {
      break;
    }

    const payload = (await response.json()) as {
      data?: {
        object?: {
          asMovePackage?: {
            packageVersionsBefore?: PackageVersionPage;
            packageVersionsAfter?: PackageVersionPage;
          };
        };
      };
      errors?: Array<{ message?: string }>;
    };

    if (payload.errors?.length) {
      break;
    }

    const page =
      input.direction === "before"
        ? payload.data?.object?.asMovePackage?.packageVersionsBefore
        : payload.data?.object?.asMovePackage?.packageVersionsAfter;
    nodes.push(...(page?.nodes ?? []));
    cursor = page?.pageInfo?.endCursor ?? undefined;
    hasNextPage = Boolean(page?.pageInfo?.hasNextPage);
  }

  return nodes;
}

interface PackageVersionPage {
  pageInfo?: { hasNextPage?: boolean; endCursor?: string | null };
  nodes?: Array<{ address?: string; version?: string | number; digest?: string }>;
}

async function fetchWithRetry(endpoint: string, init: RequestInit): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const response = await fetch(endpoint, init);
      if (response.ok || (response.status < 500 && response.status !== 429)) {
        return response;
      }
      lastError = new Error(`GraphQL HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
  }
  if (lastError instanceof Error) throw lastError;
  throw new Error("GraphQL fetch failed");
}

function emptyMetadata(packageId: string, error: string, endpoint?: string): SuiPackageMetadata {
  return {
    packageId,
    moduleNames: [],
    functions: [],
    linkage: [],
    previousVersions: [],
    laterVersions: [],
    hasMorePreviousVersions: false,
    hasMoreLaterVersions: false,
    ...(endpoint ? { endpoint } : {}),
    fetched: false,
    error
  };
}

function metadataFindings(metadata: SuiPackageMetadata): SecurityFinding[] {
  if (metadata.fetched) {
    return [];
  }

  return [
    {
      ruleId: "SUI-SOURCE-001",
      title: "Sui package metadata could not be fetched",
      description:
        "Packsight could not fetch Sui package metadata from the configured GraphQL endpoint, so on-chain package coverage is incomplete.",
      severity: "info",
      confidence: "confirmed",
      status: "open",
      chainFamily: "sui",
      evidence: [
        {
          type: "missing_information",
          value: metadata.error ?? "Sui GraphQL metadata unavailable"
        }
      ],
      affectedComponents: [metadata.packageId],
      impact: "On-chain module and checkpoint data are unavailable for this scan.",
      recommendation: "Retry with a reachable Sui GraphQL endpoint or provide a custom RPC endpoint.",
      limitations: ["This does not imply the package is safe or unsafe."]
    }
  ];
}

function versionFindings(metadata: SuiPackageMetadata): SecurityFinding[] {
  if (!metadata.fetched) return [];

  const findings: SecurityFinding[] = [];
  if (metadata.laterVersions.length > 0) {
    const latest = metadata.laterVersions[metadata.laterVersions.length - 1];
    findings.push({
      ruleId: "SUI-VERSION-001",
      title: "Scanned package is not the latest package version",
      description:
        `The scanned package is version ${metadata.version ?? "unknown"}, and Sui GraphQL returned later package versions through ${latest?.version ?? "unknown"}. ` +
        "Older Sui package IDs can remain callable unless source-level guards or state migration disable them.",
      severity: "medium",
      confidence: metadata.functions.length > 0 ? "high" : "medium",
      status: "open",
      chainFamily: "sui",
      evidence: [
        {
          type: "onchain_package_version",
          value: `${metadata.packageId}@${metadata.version ?? "unknown"}`,
          source: "onchain"
        },
        ...metadata.laterVersions.slice(0, 5).map((version): Evidence => ({
          type: "later_package_version",
          value: `${version.address}@${version.version}`,
          source: "onchain"
        }))
      ],
      affectedComponents: [metadata.packageId],
      impact:
        "Users or integrations may still be able to call this older package ID. The scanner has not proven that live protocol state accepts those calls.",
      recommendation:
        "Review whether this package ID is intentionally retained. Provide source so packsight can check version gates on exposed functions and confirm whether legacy paths abort.",
      limitations: [
        "Runtime reachability was not simulated.",
        "Source-level version gates could not be checked without source.",
        "Sui package existence and public functions do not by themselves prove asset impact."
      ]
    });
  }

  if (metadata.hasMorePreviousVersions || metadata.hasMoreLaterVersions) {
    findings.push({
      ruleId: "SUI-VERSION-001",
      title: "Package version history was truncated by scan page limits",
      description: "Sui GraphQL reported more package versions than the MVP fetched in this scan.",
      severity: "info",
      confidence: "confirmed",
      status: "open",
      chainFamily: "sui",
      evidence: [
        {
          type: "pagination",
          value: `previous=${metadata.hasMorePreviousVersions}; later=${metadata.hasMoreLaterVersions}`,
          source: "onchain"
        }
      ],
      affectedComponents: [metadata.packageId],
      impact: "The version table may not include every historical package ID.",
      recommendation: "Fetch all package-version pages before final audit use.",
      limitations: ["This is a coverage limitation, not a vulnerability."]
    });
  }

  return findings;
}

function previousVersionFindings(metadata: SuiPackageMetadata, previousMetadata: SuiPackageMetadata[]): SecurityFinding[] {
  if (!metadata.fetched || metadata.laterVersions.length > 0 || metadata.previousVersions.length === 0) {
    return [];
  }

  const inspectedCallableFunctions = previousMetadata.flatMap((legacyMetadata) =>
    legacyMetadata.functions
      .filter((moveFunction) => interfaceReachable(moveFunction) === true)
      .map((moveFunction) => ({
        legacyMetadata,
        moveFunction
      }))
  );

  if (inspectedCallableFunctions.length === 0) {
    return [
      {
        ruleId: "SUI-VERSION-007",
        title: "Previous package versions were found but callable legacy interfaces were not confirmed",
        description:
          `The scanned package appears to be the latest version ${metadata.version ?? "unknown"}, and Sui GraphQL returned ${metadata.previousVersions.length} previous package version(s). ` +
          "Packsight could not confirm callable legacy interfaces from the fetched previous-version metadata.",
        severity: "info",
        confidence: previousMetadata.length > 0 ? "medium" : "low",
        status: "open",
        chainFamily: "sui",
        evidence: metadata.previousVersions.slice(0, 10).map((version): Evidence => ({
          type: "previous_package_version",
          value: `${version.address}@${version.version}`,
          source: "onchain"
        })),
        affectedComponents: metadata.previousVersions.map((version) => version.address),
        impact: "Older package IDs may still exist, but Packsight did not observe callable legacy functions in the fetched metadata.",
        recommendation: "Fetch all package-version pages and provide exact source if this package lineage is security-sensitive.",
        limitations: ["This is a coverage finding, not proof that previous packages are safe."]
      }
    ];
  }

  return [
    {
      ruleId: "SUI-VERSION-007",
      title: "Previous package versions expose callable legacy interfaces",
      description:
        `The scanned package appears to be the latest version ${metadata.version ?? "unknown"}, but Packsight found ${inspectedCallableFunctions.length} public or entry function(s) across ${previousMetadata.length} previous package version(s). ` +
        "Older Sui package IDs can remain callable unless source-level guards, capabilities, or state migration disable the old paths.",
      severity: "medium",
      confidence: "high",
      status: "open",
      chainFamily: "sui",
      evidence: inspectedCallableFunctions.slice(0, 10).map(({ legacyMetadata, moveFunction }): Evidence => ({
        type: "previous_version_callable_function",
        value: `${legacyMetadata.packageId}@${legacyMetadata.version ?? "unknown"}::${moveFunction.moduleName}::${moveFunction.name}`,
        source: "onchain"
      })),
      affectedComponents: Array.from(new Set(inspectedCallableFunctions.map(({ legacyMetadata }) => legacyMetadata.packageId))),
      impact:
        "Users or privileged integrations may still be able to call older package IDs. Packsight has not proven that live protocol state accepts every old call.",
      recommendation:
        "Review previous package functions for version gates or shared-state checks, then simulate high-risk old calls with production-like objects and capabilities.",
      limitations: [
        "Runtime reachability was not simulated.",
        "Source-level version gates could not be checked without exact source for each previous package.",
        "Sui package existence and public functions do not by themselves prove asset impact."
      ]
    }
  ];
}

function versionFunctionDiffFindings(
  metadata: SuiPackageMetadata,
  latestMetadata: SuiPackageMetadata | undefined
): SecurityFinding[] {
  if (!latestMetadata?.fetched || metadata.laterVersions.length === 0) {
    return [];
  }

  const diffs = buildVersionFunctionDiffs(metadata, latestMetadata);
  const sensitiveStillPresent = diffs.filter(
    (diff) =>
      diff.status === "present_in_upgrade" &&
      diff.valueSensitive === true &&
      (diff.visibility.includes("public") || diff.isEntry)
  );

  if (sensitiveStillPresent.length === 0) {
    return [];
  }

  return [
    {
      ruleId: "SUI-VERSION-006",
      title: "Sensitive legacy functions are still present in the upgraded package",
      description:
        `${sensitiveStillPresent.length} sensitive public or entry function(s) exposed by the scanned legacy package also exist in the upgraded package. ` +
        "This helps auditors identify old package functions that likely map to maintained logic and may need explicit legacy-call blocking.",
      severity: "medium",
      confidence: "high",
      status: "open",
      chainFamily: "sui",
      evidence: sensitiveStillPresent.slice(0, 10).map((diff): Evidence => ({
        type: "legacy_function_present_in_upgrade",
        value: `${diff.name} ${metadata.packageId}@${metadata.version ?? "unknown"} -> ${diff.comparedToAddress}@${
          diff.comparedToVersion ?? "unknown"
        }`,
        source: "onchain"
      })),
      affectedComponents: sensitiveStillPresent.slice(0, 20).map((diff) => diff.name),
      impact:
        "If protocol state still accepts calls from the old package ID, users may be able to execute older copies of functions that continue to exist in the active package.",
      recommendation:
        "Review these functions for version gates or shared-state checks that abort calls from stale package versions, then simulate high-risk paths with production-like state.",
      limitations: [
        "Function presence in the upgraded package is an interface comparison, not proof of runtime reachability.",
        "Source-level deprecation comments and guards require verified source or repository input."
      ]
    }
  ];
}

function buildVersionFunctionDiffs(
  metadata: SuiPackageMetadata,
  latestMetadata: SuiPackageMetadata | undefined
): VersionFunctionDiff[] {
  if (!latestMetadata?.fetched || metadata.laterVersions.length === 0) {
    return [];
  }

  const legacyFunctions = new Map(metadata.functions.map((moveFunction) => [functionKey(moveFunction), moveFunction]));
  const latestFunctions = new Map(latestMetadata.functions.map((moveFunction) => [functionKey(moveFunction), moveFunction]));
  const comparedToAddress = latestMetadata.packageId;
  const comparedToVersion = latestMetadata.version;

  const oldDiffs = metadata.functions.map((moveFunction): VersionFunctionDiff => ({
    name: `${moveFunction.moduleName}::${moveFunction.name}`,
    module: moveFunction.moduleName,
    packageAddress: metadata.packageId,
    ...(metadata.version ? { packageVersion: metadata.version } : {}),
    comparedToAddress,
    ...(comparedToVersion ? { comparedToVersion } : {}),
    status: latestFunctions.has(functionKey(moveFunction)) ? "present_in_upgrade" : "removed_in_upgrade",
      visibility: normalizeVisibility(moveFunction),
      isEntry: moveFunction.isEntry,
      accessibility: accessibilityFor(moveFunction).accessibility,
      accessibilityReason: accessibilityFor(moveFunction).reason,
      valueSensitive: isSensitiveMoveFunction(moveFunction)
  }));

  const addedDiffs = latestMetadata.functions
    .filter((moveFunction) => !legacyFunctions.has(functionKey(moveFunction)))
    .map((moveFunction): VersionFunctionDiff => ({
      name: `${moveFunction.moduleName}::${moveFunction.name}`,
      module: moveFunction.moduleName,
      packageAddress: latestMetadata.packageId,
      ...(latestMetadata.version ? { packageVersion: latestMetadata.version } : {}),
      comparedToAddress: metadata.packageId,
      ...(metadata.version ? { comparedToVersion: metadata.version } : {}),
      status: "added_in_upgrade",
      visibility: normalizeVisibility(moveFunction),
      isEntry: moveFunction.isEntry,
      accessibility: accessibilityFor(moveFunction).accessibility,
      accessibilityReason: accessibilityFor(moveFunction).reason,
      valueSensitive: isSensitiveMoveFunction(moveFunction)
    }));

  return [...oldDiffs, ...addedDiffs].sort((left, right) => left.name.localeCompare(right.name));
}

function packageLinkFindings(
  metadata: SuiPackageMetadata,
  latestMetadata: SuiPackageMetadata | undefined
): SecurityFinding[] {
  if (!latestMetadata?.fetched || metadata.linkage.length === 0) return [];
  const upgradedLinks = buildPackageLinks(metadata, latestMetadata).filter((link) => link.status === "upgraded_in_latest");
  if (upgradedLinks.length === 0) return [];

  return [
    {
      ruleId: "SUI-LINKAGE-001",
      title: "Linked packages changed in the upgraded package",
      description:
        `${upgradedLinks.length} package linkage entr${upgradedLinks.length === 1 ? "y" : "ies"} used by the scanned legacy package resolve differently in the latest package.`,
      severity: "medium",
      confidence: "high",
      status: "open",
      chainFamily: "sui",
      evidence: upgradedLinks.slice(0, 10).flatMap((link): Evidence[] => [
        {
          type: "legacy_linkage",
          value: `${link.originalPackageId} -> ${link.resolvedPackageId}@${link.resolvedVersion ?? "unknown"}`,
          source: "onchain"
        },
        {
          type: "latest_linkage",
          value: `${link.originalPackageId} -> ${link.latestResolvedPackageId ?? "unknown"}@${
            link.latestResolvedVersion ?? "unknown"
          }`,
          source: "onchain"
        }
      ]),
      affectedComponents: upgradedLinks.map((link) => link.originalPackageId),
      impact:
        "The legacy package was compiled against older linked package resolutions. Auditors should verify whether those older linked packages remain safe and intentionally callable.",
      recommendation:
        "Review every upgraded linkage entry, compare dependency behavior across versions, and confirm legacy functions cannot rely on stale dependency state.",
      limitations: ["Package linkage comparison does not simulate a transaction path."]
    }
  ];
}

function buildPackageLinks(
  metadata: SuiPackageMetadata,
  latestMetadata: SuiPackageMetadata | undefined
): PackageLink[] {
  const latestByOriginal = new Map((latestMetadata?.linkage ?? []).map((link) => [link.originalId, link]));
  return metadata.linkage.map((link): PackageLink => {
    const latestLink = latestByOriginal.get(link.originalId);
    const status = linkedPackageStatus(link, latestMetadata);
    return {
      sourcePackageAddress: metadata.packageId,
      ...(metadata.version ? { sourcePackageVersion: metadata.version } : {}),
      originalPackageId: link.originalId,
      resolvedPackageId: link.upgradedId,
      resolvedVersion: link.version,
      ...(latestLink ? { latestResolvedPackageId: latestLink.upgradedId, latestResolvedVersion: latestLink.version } : {}),
      status,
      relationship: "sui_linkage",
      evidence: [
        {
          type: "sui_linkage",
          value: `${link.originalId} -> ${link.upgradedId}@${link.version}`,
          source: "onchain"
        }
      ]
    };
  });
}

function linkedPackageStatus(
  link: SuiLinkage,
  latestMetadata: SuiPackageMetadata | undefined
): PackageLink["status"] {
  if (!latestMetadata?.fetched) return "unknown";
  const latestLink = latestMetadata.linkage.find((candidate) => candidate.originalId === link.originalId);
  if (!latestLink) return "missing_in_latest";
  if (latestLink.upgradedId !== link.upgradedId || latestLink.version !== link.version) return "upgraded_in_latest";
  return "unchanged";
}

function functionKey(moveFunction: SuiMoveFunction): string {
  return `${moveFunction.moduleName}::${moveFunction.name}`;
}

function normalizeVisibility(moveFunction: SuiMoveFunction): string {
  return moveFunction.isEntry ? `${moveFunction.visibility.toLowerCase()} entry` : moveFunction.visibility.toLowerCase();
}

function accessibilityFor(moveFunction: SuiMoveFunction): {
  accessibility: NonNullable<CallableSurface["accessibility"]>;
  reason: string;
} {
  const visibility = moveFunction.visibility.toUpperCase();
  if (moveFunction.isEntry) {
    return {
      accessibility: "transaction_entry",
      reason: "Sui GraphQL marks this function as entry, so it is exposed as a transaction entry point at the interface level."
    };
  }
  if (visibility === "PUBLIC") {
    return {
      accessibility: "public_move_call",
      reason: "Sui GraphQL marks this function public. It is part of the public Move interface, but runtime success still depends on arguments and state checks."
    };
  }
  if (visibility === "FRIEND") {
    return {
      accessibility: "friend_only",
      reason: "Sui GraphQL marks this function friend-visible, so it is only callable from declared friend modules."
    };
  }
  if (visibility === "PRIVATE") {
    return {
      accessibility: "private",
      reason: "Sui GraphQL marks this function private, so it is not externally callable as a package interface function."
    };
  }
  return {
    accessibility: "unknown",
    reason: "Sui GraphQL did not expose a recognized visibility for this function."
  };
}

function interfaceReachable(moveFunction: SuiMoveFunction): boolean | "unknown" {
  const accessibility = accessibilityFor(moveFunction).accessibility;
  if (accessibility === "transaction_entry" || accessibility === "public_move_call") return true;
  if (accessibility === "friend_only" || accessibility === "private") return false;
  return "unknown";
}

function buildCallableSurface(
  metadata: SuiPackageMetadata,
  sourceFunctions: Array<{ moduleName: string; functionName: string; mutatesState: boolean | "unknown" }>
): CallableSurface[] {
  if (metadata.functions.length > 0) {
    return metadata.functions.map((moveFunction): CallableSurface => ({
      name: moveFunction.fullyQualifiedName,
      module: moveFunction.moduleName,
      address: metadata.packageId,
      versionIdentifier: metadata.version ?? metadata.packageId,
      visibility: normalizeVisibility(moveFunction),
      accessibility: accessibilityFor(moveFunction).accessibility,
      accessibilityReason: accessibilityFor(moveFunction).reason,
      deprecated: metadata.laterVersions.length > 0 ? true : "unknown",
      reachable: interfaceReachable(moveFunction),
      mutatesState: inferMutationRisk(moveFunction, sourceFunctions) === "state_mutation_likely" ? true : "unknown",
      valueSensitive: isSensitiveMoveFunction(moveFunction)
    }));
  }

  return metadata.moduleNames.map((moduleName): CallableSurface => ({
    name: `${metadata.packageId}::${moduleName}::*`,
    module: moduleName,
    address: metadata.packageId,
    versionIdentifier: metadata.version ?? metadata.packageId,
    visibility: "public_or_entry_unknown",
    deprecated: metadata.laterVersions.length > 0 ? true : "unknown",
    reachable: "unknown",
    mutatesState: "unknown",
    valueSensitive: "unknown"
  }));
}

function buildRuntimeChecks(
  metadata: SuiPackageMetadata,
  sourceFunctions: Array<{
    moduleName: string;
    functionName: string;
    mutatesState: boolean | "unknown";
    hasVersionGate: boolean;
  }>,
  sourceAvailable: boolean
): RuntimeCheck[] {
  return metadata.functions
    .filter((moveFunction) => interfaceReachable(moveFunction) === true)
    .map((moveFunction): RuntimeCheck => {
      const accessibility = accessibilityFor(moveFunction).accessibility;
      const mutationRisk = inferMutationRisk(moveFunction, sourceFunctions);
      const guardStatus = inferGuardStatus(moveFunction, metadata, sourceFunctions, sourceAvailable);
      const legacy = metadata.laterVersions.length > 0;
      const requiredEvidence = [
        "Exact live shared objects or owned objects accepted by the function parameters.",
        "Dry-run or transaction simulation showing whether the old package call aborts or succeeds.",
        "Source or decompiled bytecode evidence for package-version/current-version checks.",
        "Capability and signer ownership review for privileged parameters."
      ];

      return {
        functionName: `${moveFunction.moduleName}::${moveFunction.name}`,
        module: moveFunction.moduleName,
        packageAddress: metadata.packageId,
        ...(metadata.version ? { packageVersion: metadata.version } : {}),
        accessibility,
        interfaceReachable: true,
        mutationRisk,
        guardStatus,
        runtimeStatus: legacy ? "simulation_required" : "not_simulated",
        parameters: moveFunction.parameters,
        returns: moveFunction.returns,
        requiredEvidence,
        notes: runtimeNotes(moveFunction, mutationRisk, guardStatus, legacy)
      };
    });
}

function inferMutationRisk(
  moveFunction: SuiMoveFunction,
  sourceFunctions: Array<{ moduleName: string; functionName: string; mutatesState: boolean | "unknown" }>
): RuntimeCheck["mutationRisk"] {
  const sourceFunction = sourceFunctions.find(
    (candidate) => candidate.moduleName === moveFunction.moduleName && candidate.functionName === moveFunction.name
  );
  if (sourceFunction?.mutatesState === true) return "state_mutation_likely";

  const allTypes = [...moveFunction.parameters, ...moveFunction.returns];
  const hasMutableStateParam = moveFunction.parameters.some(
    (parameter) => parameter.includes("&mut") && !parameter.includes("tx_context::TxContext")
  );
  if (hasMutableStateParam) return "state_mutation_likely";

  const hasValueFlow = allTypes.some((item) => /\b(Coin|Balance|Treasury|Cap|Receipt)\b/.test(item));
  const sensitiveName = isSensitiveFunctionName(moveFunction.name) === true;
  if (hasValueFlow || sensitiveName) return "state_mutation_possible";

  if (moveFunction.parameters.every((parameter) => !parameter.includes("&mut"))) return "read_only_likely";
  return "unknown";
}

function inferGuardStatus(
  moveFunction: SuiMoveFunction,
  metadata: SuiPackageMetadata,
  sourceFunctions: Array<{ moduleName: string; functionName: string; hasVersionGate: boolean }>,
  sourceAvailable: boolean
): RuntimeCheck["guardStatus"] {
  if (metadata.laterVersions.length === 0) return "not_applicable";
  const sourceFunction = sourceFunctions.find(
    (candidate) => candidate.moduleName === moveFunction.moduleName && candidate.functionName === moveFunction.name
  );
  if (!sourceAvailable || !sourceFunction) return "unknown_source_unavailable";
  return sourceFunction.hasVersionGate ? "source_guard_detected" : "source_guard_missing";
}

function runtimeNotes(
  moveFunction: SuiMoveFunction,
  mutationRisk: RuntimeCheck["mutationRisk"],
  guardStatus: RuntimeCheck["guardStatus"],
  legacy: boolean
): string[] {
  const notes: string[] = [];
  if (legacy) {
    notes.push("A later package exists, so this old package function needs stale-package runtime proof.");
  }
  if (mutationRisk === "state_mutation_likely") {
    notes.push("Signature or source indicates likely state mutation, usually through mutable object parameters.");
  } else if (mutationRisk === "state_mutation_possible") {
    notes.push("Name, return type or value object parameters indicate possible state impact.");
  } else if (mutationRisk === "read_only_likely") {
    notes.push("No mutable parameters were observed in the on-chain signature; runtime review can usually be lower priority.");
  }
  if (guardStatus === "unknown_source_unavailable") {
    notes.push("No verified source was supplied, so packsight cannot confirm whether a version gate makes this old call abort.");
  }
  if (moveFunction.parameters.length === 0) {
    notes.push("No parameters are required by the interface.");
  }
  return notes;
}

function coverageFor(
  metadata: SuiPackageMetadata,
  sourceAvailable: boolean,
  lockfilePresent: boolean
): DataCoverage {
  const sourceCode: CoverageState = sourceAvailable ? "complete" : "unavailable";
  return {
    onchainMetadata: metadata.fetched ? "partial" : "unavailable",
    sourceCode,
    historicalVersions:
      metadata.fetched && !metadata.hasMorePreviousVersions && !metadata.hasMoreLaterVersions ? "complete" : "partial",
    interfaceData: metadata.functions.length > 0 || metadata.moduleNames.length > 0 ? "partial" : "unavailable",
    dependencyGraph: metadata.linkage.length > 0 ? "partial" : sourceAvailable ? (lockfilePresent ? "complete" : "partial") : "unavailable",
    runtimeReachability: "not_tested"
  };
}

function normalizePackageId(packageId: string): string {
  const trimmed = packageId.trim();
  return trimmed.startsWith("0x") ? trimmed.toLowerCase() : `0x${trimmed.toLowerCase()}`;
}

function normalizePackageVersions(nodes: Array<{ address?: string; version?: string | number; digest?: string }>): SuiPackageVersion[] {
  return nodes
    .filter((node) => node.address && node.version !== undefined)
    .map((node) => ({
      address: normalizePackageId(node.address as string),
      version: String(node.version),
      ...(node.digest ? { digest: node.digest } : {})
    }));
}

function extractGraphqlFunctions(
  modules: Array<{
    name?: string;
    functions?: {
      nodes?: Array<{
        name?: string;
        fullyQualifiedName?: string;
        isEntry?: boolean;
        visibility?: string;
        parameters?: Array<{ repr?: string }>;
        return?: Array<{ repr?: string }>;
      }>;
    };
  }>,
  packageId: string
): SuiMoveFunction[] {
  return modules.flatMap((module) =>
    (module.functions?.nodes ?? [])
      .filter((moveFunction) => module.name && moveFunction.name)
      .map((moveFunction) => ({
        moduleName: module.name as string,
        name: moveFunction.name as string,
        fullyQualifiedName:
          moveFunction.fullyQualifiedName ?? `${packageId}::${module.name as string}::${moveFunction.name as string}`,
        isEntry: Boolean(moveFunction.isEntry),
        visibility: moveFunction.visibility ?? "UNKNOWN",
        parameters: (moveFunction.parameters ?? []).map((parameter) => parameter.repr).filter((repr): repr is string => Boolean(repr)),
        returns: (moveFunction.return ?? []).map((returnType) => returnType.repr).filter((repr): repr is string => Boolean(repr))
      }))
  );
}

function isSensitiveFunctionName(name: string): boolean | "unknown" {
  const normalized = name.replace(/_/g, " ");
  return /\b(withdraw|vault|treasury|reward|claim|admin|cap|mint|burn|transfer|swap|commission|slippage|fee|config|amount|repay|remove|set)\b/i.test(normalized)
    ? true
    : false;
}

function isSensitiveMoveFunction(moveFunction: SuiMoveFunction): boolean | "unknown" {
  if (isSensitiveFunctionName(moveFunction.name) === true) return true;
  const signatureText = [...moveFunction.parameters, ...moveFunction.returns].join(" ");
  if (
    /\b(Coin|Balance|Treasury|AdminCap|Cap|FlashMintReceipt|GlobalConfig|AccountRequest|USDB)\b/.test(signatureText) ||
    /&mut\s+.*::(config|treasury|admin|coin|balance)::/i.test(signatureText)
  ) {
    return true;
  }
  if (moveFunction.parameters.length > 0 || moveFunction.returns.length > 0) return false;
  return "unknown";
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
