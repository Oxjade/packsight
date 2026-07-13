"use client";

import { useMemo, useState } from "react";
import type { ScanReport, Severity } from "@packsight/report-schema";
import { Download, FileJson, FileText } from "lucide-react";

const severityFilters: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];

export function ReportClient({ report }: { report: ScanReport }) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const packageLinks = report.packageLinks ?? [];
  const runtimeChecks = report.runtimeChecks ?? [];
  const terms = reportSurfaceTerms(report.target.chainFamily);
  const findings = useMemo(
    () => report.findings.filter((finding) => severity === "all" || finding.severity === severity),
    [report.findings, severity]
  );
  const developerFocus = useMemo(() => buildDeveloperFocusSummary(report), [report]);

  return (
    <div className="page">
      <section className="report-header">
        <div className="score" aria-label={`Security hygiene score ${report.score}, grade ${report.grade}`}>
          <div>
            <strong>{report.grade}</strong>
            <span className="mono">{report.score}/100</span>
          </div>
        </div>
        <div className="report-band">
          <h1>Security hygiene report</h1>
          <p>{report.summary.headline}</p>
          <p className="mono">
            {[report.target.chainFamily, report.target.network, report.target.chainId ? `chain ${report.target.chainId}` : undefined, report.target.address]
              .filter(Boolean)
              .join(" · ")}
          </p>
          <div className="report-actions" aria-label="Report downloads">
            <button className="button" onClick={() => downloadJsonReport(report)} type="button">
              <FileJson size={17} aria-hidden="true" />
              JSON
            </button>
            <button className="button secondary" onClick={() => downloadMarkdownReport(report)} type="button">
              <FileText size={17} aria-hidden="true" />
              Markdown
            </button>
            <button className="button secondary" onClick={() => window.print()} type="button">
              <Download size={17} aria-hidden="true" />
              PDF
            </button>
          </div>
        </div>
      </section>

      <section className="section report-band">
        <h2>Executive summary</h2>
        <SummaryList title="Confirmed facts" items={report.summary.confirmedFacts} />
        <SummaryList title="Static-analysis findings" items={report.summary.staticAnalysisFindings} />
        <SummaryList title="Heuristic findings" items={report.summary.heuristicFindings} />
        <SummaryList title="Missing information" items={report.summary.missingInformation} />
        <SummaryList title="Manual-review recommendations" items={report.summary.manualReviewRecommendations} />
      </section>

      <section className="section report-band">
        <h2>Data coverage and limitations</h2>
        <div className="coverage-grid">
          {Object.entries(report.dataCoverage).map(([key, value]) => (
            <div className="coverage-item" key={key}>
              <span>{key}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="section report-band developer-focus">
        <h2>Developer focus</h2>
        <p>{developerFocus}</p>
      </section>

      <PackageMap report={report} />

      <section className="section">
        <h2>Findings</h2>
        <div className="filters" aria-label="Finding filters">
          {severityFilters.map((filter) => (
            <button
              className={`filter-button ${severity === filter ? "active" : ""}`}
              key={filter}
              onClick={() => setSeverity(filter)}
              type="button"
            >
              {filter}
            </button>
          ))}
        </div>
        <div className="table-wrap">
          <table className="findings-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Finding</th>
                <th>Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={`${finding.ruleId}-${finding.title}`}>
                  <td className="mono">{finding.ruleId}</td>
                  <td>
                    <span className={`badge ${finding.severity}`}>{finding.severity}</span>
                  </td>
                  <td>{finding.confidence}</td>
                  <td>
                    <strong>{finding.title}</strong>
                    <p>{finding.description}</p>
                  </td>
                  <td>{finding.recommendation}</td>
                </tr>
              ))}
              {findings.length === 0 ? (
                <tr>
                  <td colSpan={5}>No findings match the selected filter.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <ReportTable
        title="Version history"
        headers={["Identifier", "Address", "Source verified", "Version status"]}
        rows={report.versions.map((version) => [
          version.identifier,
          version.address ?? "unknown",
          yesNo(version.verified),
          version.activeStatus
        ])}
      />

      <ReportTable
        title="Callable surface"
        headers={["Name", "Module", "Access", "Reachable", "Upgrade status", "Sensitive"]}
        rows={report.callableSurface.map((item) => [
          item.name,
          item.module ?? "unknown",
          item.accessibility ?? item.visibility,
          knownBool(item.reachable),
          upgradeStatus(item.deprecated),
          sensitivityLabel(item.valueSensitive)
        ])}
      />

      <ReportTable
        title={terms.diffTitle}
        headers={["Function", "Status", "Access", terms.legacyHeader, terms.comparedHeader, "Sensitive"]}
        rows={report.versionFunctionDiffs.map((item) => [
          item.name,
          item.status,
          item.accessibility ?? item.visibility,
          `${item.packageAddress}${item.packageVersion ? ` @ v${item.packageVersion}` : ""}`,
          `${item.comparedToAddress}${item.comparedToVersion ? ` @ v${item.comparedToVersion}` : ""}`,
          sensitivityLabel(item.valueSensitive)
        ])}
      />

      <ReportTable
        title={terms.linkageTitle}
        headers={terms.linkageHeaders}
        rows={packageLinks.map((link) => [
          link.originalPackageId,
          `${link.resolvedPackageId}${link.resolvedVersion ? ` @ v${link.resolvedVersion}` : ""}`,
          report.target.chainFamily === "solana"
            ? link.evidence.map((item) => displayRelationship(item.type)).join(", ") || "onchain"
            : link.latestResolvedPackageId
              ? `${link.latestResolvedPackageId}${link.latestResolvedVersion ? ` @ v${link.latestResolvedVersion}` : ""}`
              : "not found",
          link.status,
          displayRelationship(link.relationship)
        ])}
      />

      <ReportTable
        title="Runtime and state proof checklist"
        headers={["Function", "Mutation hint", "Guard evidence", "Runtime status", "Parameters"]}
        rows={runtimeChecks.map((check) => [
          check.functionName,
          check.mutationRisk,
          check.guardStatus,
          check.runtimeStatus,
          check.parameters.length > 0 ? check.parameters.join(" | ") : "none"
        ])}
      />

      <ReportTable
        title="Dependencies"
        headers={["Ecosystem", "Name", "Resolved", "Source", "Deprecated", "Vulnerable"]}
        rows={report.dependencies.map((dependency) => [
          dependency.ecosystem,
          dependency.name,
          dependency.requestedVersion ?? dependency.resolvedVersion ?? "unknown",
          dependency.source ?? "unknown",
          knownBool(dependency.deprecated),
          knownBool(dependency.vulnerable)
        ])}
      />

      <section className="section report-band">
        <h2>Remediation checklist</h2>
        <ul>
          {report.findings.map((finding) => (
            <li key={`${finding.ruleId}-remediate`}>
              <span className="mono">{finding.ruleId}</span>: {finding.recommendation}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function yesNo(value: boolean): string {
  return value ? "yes" : "no";
}

function knownBool(value: boolean | "unknown"): string {
  if (value === "unknown") return "unknown";
  return value ? "yes" : "no";
}

function sensitivityLabel(value: boolean | "unknown"): string {
  if (value === true) return "sensitive";
  if (value === false) return "not flagged";
  return "unknown";
}

function upgradeStatus(value: boolean | "unknown"): string {
  if (value === true) return "legacy/deprecated";
  if (value === false) return "current";
  return "unknown";
}

function downloadJsonReport(report: ScanReport) {
  downloadBlob({
    filename: `${reportFilenameBase(report)}.json`,
    contents: `${JSON.stringify(report, null, 2)}\n`,
    type: "application/json"
  });
}

function downloadMarkdownReport(report: ScanReport) {
  downloadBlob({
    filename: `${reportFilenameBase(report)}.md`,
    contents: reportToMarkdown(report),
    type: "text/markdown"
  });
}

function downloadBlob({ filename, contents, type }: { filename: string; contents: string; type: string }) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function reportFilenameBase(report: ScanReport): string {
  const target = report.target.address ?? report.id;
  return `packsight-${report.target.chainFamily}-${report.target.network}-${target}`.replace(/[^a-zA-Z0-9._-]+/g, "-");
}

function reportToMarkdown(report: ScanReport): string {
  const terms = reportSurfaceTerms(report.target.chainFamily);
  const target = [report.target.chainFamily, report.target.network, report.target.address].filter(Boolean).join(" / ");
  return [
    `# PackSight Security Hygiene Report`,
    "",
    `- Scan ID: ${report.id}`,
    `- Target: ${target}`,
    report.target.chainId ? `- Chain ID: ${report.target.chainId}` : undefined,
    `- Status: ${report.status}`,
    `- Score: ${report.score}/100`,
    `- Grade: ${report.grade}`,
    `- Started: ${report.startedAt}`,
    report.completedAt ? `- Completed: ${report.completedAt}` : undefined,
    report.scanPoint?.chainCheckpoint ? `- Chain checkpoint: ${report.scanPoint.chainCheckpoint}` : undefined,
    report.scanPoint?.blockNumber ? `- Block number: ${report.scanPoint.blockNumber}` : undefined,
    report.scanPoint?.slot ? `- Slot: ${report.scanPoint.slot}` : undefined,
    report.scanPoint?.chainId ? `- RPC chain ID: ${report.scanPoint.chainId}` : undefined,
    report.scanPoint?.rpcUrl ? `- RPC: ${report.scanPoint.rpcUrl}` : undefined,
    "",
    "## Executive Summary",
    "",
    report.summary.headline,
    "",
    markdownList("Confirmed facts", report.summary.confirmedFacts),
    markdownList("Static-analysis findings", report.summary.staticAnalysisFindings),
    markdownList("Heuristic findings", report.summary.heuristicFindings),
    markdownList("Missing information", report.summary.missingInformation),
    markdownList("Manual-review recommendations", report.summary.manualReviewRecommendations),
    "## Developer Focus",
    "",
    buildDeveloperFocusSummary(report),
    "",
    "## Data Coverage",
    "",
    markdownTable(["Area", "Status"], Object.entries(report.dataCoverage)),
    "",
    "## Findings",
    "",
    report.findings.length > 0
      ? markdownTable(
          ["Rule", "Severity", "Confidence", "Finding", "Recommendation"],
          report.findings.map((finding) => [
            finding.ruleId,
            finding.severity,
            finding.confidence,
            finding.title,
            finding.recommendation
          ])
        )
      : "No findings.",
    "",
    "## Versions",
    "",
    markdownTable(
      ["Identifier", "Address", "Source verified", "Version status"],
      report.versions.map((version) => [
        version.identifier,
        version.address ?? "unknown",
        yesNo(version.verified),
        version.activeStatus
      ])
    ),
    "",
    "## Callable Surface",
    "",
    markdownTable(
      ["Name", "Module", "Access", "Reachable", "Upgrade status", "Sensitive"],
      report.callableSurface.map((item) => [
        item.name,
        item.module ?? "unknown",
        item.accessibility ?? item.visibility,
        knownBool(item.reachable),
        upgradeStatus(item.deprecated),
        sensitivityLabel(item.valueSensitive)
      ])
    ),
    "",
    `## ${terms.linkageTitle}`,
    "",
    report.packageLinks.length > 0
      ? markdownTable(
          terms.linkageHeaders,
          report.packageLinks.map((link) => [
            link.originalPackageId,
            `${link.resolvedPackageId}${link.resolvedVersion ? ` @ v${link.resolvedVersion}` : ""}`,
            report.target.chainFamily === "solana"
              ? link.evidence.map((item) => displayRelationship(item.type)).join(", ") || "onchain"
              : link.latestResolvedPackageId
                ? `${link.latestResolvedPackageId}${link.latestResolvedVersion ? ` @ v${link.latestResolvedVersion}` : ""}`
                : "not found",
            link.status,
            displayRelationship(link.relationship)
          ])
        )
      : `No ${terms.linkageTitle.toLowerCase()} data available.`,
    "",
    "## Runtime Checks",
    "",
    report.runtimeChecks.length > 0
      ? markdownTable(
          ["Function", "Mutation hint", "Guard evidence", "Runtime status", "Parameters"],
          report.runtimeChecks.map((check) => [
            check.functionName,
            check.mutationRisk,
            check.guardStatus,
            check.runtimeStatus,
            check.parameters.length > 0 ? check.parameters.join(" | ") : "none"
          ])
        )
      : "No runtime checks available.",
    ""
  ]
    .filter((line): line is string => line !== undefined)
    .join("\n");
}

function markdownList(title: string, items: string[]): string {
  if (items.length === 0) return "";
  return [`### ${title}`, "", ...items.map((item) => `- ${item}`), ""].join("\n");
}

function markdownTable(headers: string[], rows: string[][]): string {
  if (rows.length === 0) return "No data available.";
  const normalizedRows = rows.map((row) => row.map(markdownCell));
  return [
    `| ${headers.map(markdownCell).join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...normalizedRows.map((row) => `| ${row.join(" | ")} |`)
  ].join("\n");
}

function markdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function buildDeveloperFocusSummary(report: ScanReport): string {
  const terms = reportSurfaceTerms(report.target.chainFamily);
  const target = report.target.address ? shortAddress(report.target.address) : "this target";
  const currentVersion = report.versions.find((version) => version.activeStatus === "active") ?? report.versions.at(-1);
  const legacyVersions = report.versions.filter((version) => version.activeStatus === "legacy").length;
  const callableCount = report.callableSurface.filter((item) => item.reachable === true).length;
  const sensitiveCount = report.callableSurface.filter((item) => item.valueSensitive === true).length;
  const mutationChecks = report.runtimeChecks.filter(
    (check) => check.mutationRisk === "state_mutation_likely" || check.mutationRisk === "state_mutation_possible"
  );
  const notSimulatedCount = report.runtimeChecks.filter((check) => check.runtimeStatus === "not_simulated").length;
  const focusNames = uniqueStrings([
    ...report.callableSurface
      .filter((item) => item.reachable === true && item.valueSensitive === true && item.accessibility !== "private")
      .map((item) => displayFunctionName(item.name)),
    ...mutationChecks.map((check) => displayFunctionName(check.functionName))
  ]).slice(0, 4);
  const focusText =
    focusNames.length > 0
      ? ` Prioritize examples like ${formatInlineList(focusNames)}, then expand to the rest of the value-sensitive and state-mutating surface.`
      : " Start with any public or entry functions that move value, mutate shared objects, change configuration, or touch privileged capabilities.";
  const runtimeText =
    notSimulatedCount > 0
      ? ` ${notSimulatedCount} runtime check(s) still need simulation or source confirmation, so treat this as triage evidence until those paths are proven with production-like objects.`
      : " Runtime evidence is present for the recorded checks, but developers should still confirm behavior with production-like objects before changing severity.";

  return `${target} resolves to ${currentVersion ? terms.versionLabel(currentVersion.identifier) : `the scanned ${terms.subject}`} with ${legacyVersions} legacy ${terms.versionNoun}(s), ${callableCount} reachable interface record(s), and ${sensitiveCount} value-sensitive callable item(s) in the report. Developers should focus review on ${terms.focus}; verify ${terms.verification}.${focusText}${runtimeText}`;
}

function reportSurfaceTerms(chainFamily: ScanReport["target"]["chainFamily"]): {
  subject: string;
  versionNoun: string;
  mapTitle: string;
  mapDescription: string;
  mapAria: string;
  mapSvgTitle: string;
  linkedNodeLabel: string;
  linkedCountLabel: string;
  upgradedLinksLabel: string;
  linkageTitle: string;
  linkageHeaders: string[];
  diffTitle: string;
  legacyHeader: string;
  comparedHeader: string;
  focus: string;
  verification: string;
  versionLabel: (identifier: string) => string;
} {
  if (chainFamily === "solana") {
    return {
      subject: "program",
      versionNoun: "deployment",
      mapTitle: "Program map",
      mapDescription: "Program deployment facts, upgradeability signals and callable instruction surfaces are shown as connected nodes.",
      mapAria: "Program map metrics",
      mapSvgTitle: "Interlinked Solana program account map",
      linkedNodeLabel: "linked account/program",
      linkedCountLabel: "linked accounts/programs",
      upgradedLinksLabel: "discovered links",
      linkageTitle: "Program linkage",
      linkageHeaders: ["Source account", "Resolved account", "Related account", "Status", "Relationship"],
      diffTitle: "Instruction diff",
      legacyHeader: "Legacy deployment",
      comparedHeader: "Compared deployment",
      focus:
        "instructions that move lamports or tokens, change authorities, write privileged accounts, invoke external programs, or depend on signer/PDA constraints",
      verification:
        "signer requirements, account ownership, PDA seeds, upgrade authority status, account mutability, and equivalent behavior across supplied source or IDL evidence",
      versionLabel: (identifier) => `deployment ${identifier}`
    };
  }

  if (chainFamily === "evm") {
    return {
      subject: "contract",
      versionNoun: "implementation",
      mapTitle: "Contract map",
      mapDescription: "Contract, proxy, implementation and interface evidence are shown as connected nodes when available.",
      mapAria: "Contract map metrics",
      mapSvgTitle: "Interlinked EVM contract map",
      linkedNodeLabel: "linked contract",
      linkedCountLabel: "linked contracts",
      upgradedLinksLabel: "contract links",
      linkageTitle: "Contract linkage",
      linkageHeaders: ["Original", "Scanned resolution", "Latest resolution", "Status", "Relationship"],
      diffTitle: "Implementation function diff",
      legacyHeader: "Legacy implementation",
      comparedHeader: "Compared implementation",
      focus:
        "functions that transfer value, are payable, upgrade implementations, change owners/admins, pause systems, sweep funds, mint/burn tokens, or write critical storage",
      verification:
        "the declared chain ID, RPC chain ID, proxy/admin slots, role checks, implementation source, ABI coverage, and equivalent behavior on the intended network",
      versionLabel: (identifier) => identifier.startsWith("block:") ? `scan block ${identifier.slice("block:".length)}` : `deployment ${identifier}`
    };
  }

  return {
    subject: "package",
    versionNoun: "version",
    mapTitle: "Package map",
    mapDescription: "Version lineage, upgraded package links and callable legacy surfaces are shown as connected package nodes.",
    mapAria: "Package map metrics",
    mapSvgTitle: "Interlinked package bubble map",
    linkedNodeLabel: "dependency",
    linkedCountLabel: "package links",
    upgradedLinksLabel: "upgraded links",
    linkageTitle: "Package linkage",
    linkageHeaders: ["Original", "Scanned resolution", "Latest resolution", "Status", "Relationship"],
    diffTitle: "Legacy-to-upgrade function diff",
    legacyHeader: "Legacy package",
    comparedHeader: "Compared package",
    focus:
      "functions that can move coins, perform swaps, collect commission, mutate shared state, update configuration, or require capabilities",
    verification:
      "whether each old package path has version gates, deprecation guards, capability checks, shared-object constraints, and equivalent behavior in the current package",
    versionLabel: (identifier) => `current version ${displayVersion(identifier)}`
  };
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function formatInlineList(values: string[]): string {
  if (values.length === 1) return values[0] ?? "";
  if (values.length === 2) return `${values[0] ?? ""} and ${values[1] ?? ""}`;
  const last = values[values.length - 1] ?? "";
  return `${values
    .slice(0, -1)
    .join(", ")}, and ${last}`;
}

function displayFunctionName(name: string): string {
  return name.replace(/^0x[a-fA-F0-9]+::/, "");
}

function displayRelationship(value: string): string {
  return value.replace(/_/g, " ");
}

type PackageMapRisk = "current" | "legacy-callable" | "guarded" | "dependency" | "unknown";

type PackageMapNode = {
  id: string;
  label: string;
  address: string;
  kind: "version" | "dependency";
  version?: string | undefined;
  activeStatus?: string | undefined;
  x: number;
  y: number;
  r: number;
  callableCount: number;
  sensitiveCount: number;
  runtimeCount: number;
  guardedCount: number;
  diffCount: number;
  linkCount: number;
  risk: PackageMapRisk;
};

type PackageMapEdge = {
  id: string;
  source: string;
  target: string;
  kind: "lineage" | "linkage";
  status?: string;
};

type PackageMapModel = {
  nodes: PackageMapNode[];
  edges: PackageMapEdge[];
  metrics: {
    nodes: number;
    legacyCallable: number;
    upgradedLinks: number;
    runtimeUnknown: number;
  };
};

function PackageMap({ report }: { report: ScanReport }) {
  const graph = useMemo(() => buildPackageMap(report), [report]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId) ?? graph.nodes[0];
  const terms = reportSurfaceTerms(report.target.chainFamily);

  if (graph.nodes.length === 0) {
    return null;
  }

  return (
    <section className="section package-map-section" aria-labelledby="package-map-title">
      <div className="package-map-header">
        <div>
          <h2 id="package-map-title">{terms.mapTitle}</h2>
          <p>{terms.mapDescription}</p>
        </div>
        <div className="package-map-metrics" aria-label={terms.mapAria}>
          <span>
            <strong>{graph.metrics.nodes}</strong> nodes
          </span>
          <span>
            <strong>{graph.metrics.legacyCallable}</strong> legacy callable
          </span>
          <span>
            <strong>{graph.metrics.upgradedLinks}</strong> {terms.upgradedLinksLabel}
          </span>
          <span>
            <strong>{graph.metrics.runtimeUnknown}</strong> runtime unknown
          </span>
        </div>
      </div>

      <div className="package-map-layout">
        <div className="package-map-canvas" aria-label={`Interactive ${terms.mapTitle.toLowerCase()}`}>
          <svg className="package-map-svg" viewBox="0 0 920 520" role="img" aria-labelledby="package-map-svg-title">
            <title id="package-map-svg-title">{terms.mapSvgTitle}</title>
            <g className="package-map-edges">
              {graph.edges.map((edge) => {
                const source = graph.nodes.find((node) => node.id === edge.source);
                const target = graph.nodes.find((node) => node.id === edge.target);
                if (!source || !target) return null;
                return (
                  <line
                    className={`package-map-edge ${edge.kind} ${edge.status ?? ""}`}
                    key={edge.id}
                    x1={source.x}
                    x2={target.x}
                    y1={source.y}
                    y2={target.y}
                  />
                );
              })}
            </g>
            <g className="package-map-nodes">
              {graph.nodes.map((node) => {
                const selected = selectedNode?.id === node.id;
                return (
                  <g
                    aria-label={`${node.label}, ${node.risk.replace("-", " ")}`}
                    className={`package-map-node ${node.risk} ${selected ? "selected" : ""}`}
                    key={node.id}
                    onClick={() => setSelectedNodeId(node.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedNodeId(node.id);
                      }
                    }}
                    role="button"
                    tabIndex={0}
                  >
                    <circle cx={node.x} cy={node.y} r={node.r} />
                    <text className="package-map-node-label" textAnchor="middle" x={node.x} y={node.y - 2}>
                      {node.label}
                    </text>
                    <text className="package-map-node-meta" textAnchor="middle" x={node.x} y={node.y + 14}>
                      {node.version ? `v${node.version}` : node.kind === "dependency" ? terms.linkedNodeLabel : node.kind}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        <aside className="package-map-detail" aria-live="polite">
          {selectedNode ? (
            <>
              <div>
                <span className={`badge ${riskBadgeClass(selectedNode.risk)}`}>
                  {selectedNode.risk === "dependency" ? terms.linkedNodeLabel : riskLabel(selectedNode.risk)}
                </span>
                <h3>{selectedNode.label}</h3>
                <p className="mono">{selectedNode.address}</p>
              </div>
              <dl>
                <div>
                  <dt>Version status</dt>
                  <dd>{selectedNode.activeStatus ?? selectedNode.kind}</dd>
                </div>
                <div>
                  <dt>Callable surface</dt>
                  <dd>{selectedNode.callableCount}</dd>
                </div>
                <div>
                  <dt>Value-sensitive calls</dt>
                  <dd>{selectedNode.sensitiveCount}</dd>
                </div>
                <div>
                  <dt>Runtime checks</dt>
                  <dd>{selectedNode.runtimeCount}</dd>
                </div>
                <div>
                  <dt>Guard evidence</dt>
                  <dd>{selectedNode.guardedCount}</dd>
                </div>
                <div>
                  <dt>Function diffs</dt>
                  <dd>{selectedNode.diffCount}</dd>
                </div>
                <div>
                  <dt>{terms.linkedCountLabel}</dt>
                  <dd>{selectedNode.linkCount}</dd>
                </div>
              </dl>
            </>
          ) : null}
        </aside>
      </div>

      <div className="package-map-legend" aria-label={`${terms.mapTitle} legend`}>
        <span>
          <i className="legend-dot current" /> current
        </span>
        <span>
          <i className="legend-dot legacy-callable" /> legacy callable
        </span>
        <span>
          <i className="legend-dot guarded" /> guarded
        </span>
        <span>
          <i className="legend-dot dependency" /> {terms.linkedCountLabel}
        </span>
      </div>
    </section>
  );
}

function buildPackageMap(report: ScanReport): PackageMapModel {
  const nodes = new Map<string, PackageMapNode>();
  const edges: PackageMapEdge[] = [];
  const versions = [...report.versions].sort((a, b) => numericVersion(a.identifier) - numericVersion(b.identifier));
  const activeVersion = versions.find((version) => version.activeStatus === "active") ?? versions[versions.length - 1];
  const callableByAddress = countByAddress(
    report.callableSurface,
    (item) => item.address,
    (item) => item.reachable === true
  );
  const sensitiveByAddress = countByAddress(
    report.callableSurface,
    (item) => item.address,
    (item) => item.valueSensitive === true
  );
  const runtimeByAddress = countByAddress(report.runtimeChecks, (item) => item.packageAddress);
  const guardedByAddress = countByAddress(
    report.runtimeChecks,
    (item) => item.packageAddress,
    (item) => item.guardStatus === "source_guard_detected" || item.runtimeStatus === "aborted"
  );
  const diffByAddress = countByAddress(report.versionFunctionDiffs, (item) => item.packageAddress);
  const linkByAddress = new Map<string, number>();

  for (const link of report.packageLinks) {
    increment(linkByAddress, link.sourcePackageAddress);
    increment(linkByAddress, link.originalPackageId);
    increment(linkByAddress, link.resolvedPackageId);
    if (link.latestResolvedPackageId) increment(linkByAddress, link.latestResolvedPackageId);
  }

  const legacyVersions = versions.filter((version) => version.address && version.address !== activeVersion?.address);
  const activeAddress = normalizeAddress(activeVersion?.address ?? report.target.address ?? "target");

  if (activeVersion?.address) {
    nodes.set(
      activeAddress,
      makePackageNode({
        id: activeAddress,
        address: activeVersion.address,
        label: "current",
        kind: "version",
        version: displayVersion(activeVersion.identifier),
        activeStatus: activeVersion.activeStatus,
        x: 500,
        y: 250,
        callableByAddress,
        sensitiveByAddress,
        runtimeByAddress,
        guardedByAddress,
        diffByAddress,
        linkByAddress
      })
    );
  }

  legacyVersions.forEach((version, index) => {
    if (!version.address) return;
    const angle = legacyVersions.length === 1 ? Math.PI : (-0.78 * Math.PI) + (index * 1.56 * Math.PI) / (legacyVersions.length - 1);
    const id = normalizeAddress(version.address);
    nodes.set(
      id,
      makePackageNode({
        id,
        address: version.address,
        label: `legacy ${displayVersion(version.identifier)}`,
        kind: "version",
        version: displayVersion(version.identifier),
        activeStatus: version.activeStatus,
        x: 300 + Math.cos(angle) * 185,
        y: 250 + Math.sin(angle) * 155,
        callableByAddress,
        sensitiveByAddress,
        runtimeByAddress,
        guardedByAddress,
        diffByAddress,
        linkByAddress
      })
    );
  });

  for (let index = 1; index < versions.length; index += 1) {
    const source = normalizeAddress(versions[index - 1]?.address);
    const target = normalizeAddress(versions[index]?.address);
    if (source && target && nodes.has(source) && nodes.has(target)) {
      edges.push({ id: `lineage-${source}-${target}`, source, target, kind: "lineage" });
    }
  }

  const dependencyIds = new Set<string>();
  for (const link of report.packageLinks) {
    for (const address of [link.originalPackageId, link.resolvedPackageId, link.latestResolvedPackageId].filter(Boolean)) {
      const id = normalizeAddress(address);
      if (!id || nodes.has(id)) continue;
      dependencyIds.add(id);
      nodes.set(
        id,
        makePackageNode({
          id,
          address: address ?? id,
          label: shortAddress(address ?? id),
          kind: "dependency",
          x: 720,
          y: 250,
          callableByAddress,
          sensitiveByAddress,
          runtimeByAddress,
          guardedByAddress,
          diffByAddress,
          linkByAddress
        })
      );
    }

    const source = normalizeAddress(link.sourcePackageAddress) || activeAddress;
    const target = normalizeAddress(link.latestResolvedPackageId ?? link.resolvedPackageId ?? link.originalPackageId);
    if (source && target && nodes.has(source) && nodes.has(target)) {
      edges.push({
        id: `link-${source}-${target}-${edges.length}`,
        source,
        target,
        kind: "linkage",
        status: link.status
      });
    }
  }

  Array.from(dependencyIds).forEach((id, index, list) => {
    const node = nodes.get(id);
    if (!node) return;
    const angle = list.length === 1 ? 0 : (-0.66 * Math.PI) + (index * 1.32 * Math.PI) / (list.length - 1);
    node.x = 700 + Math.cos(angle) * 145;
    node.y = 250 + Math.sin(angle) * 170;
  });

  const graphNodes = Array.from(nodes.values());
  return {
    nodes: graphNodes,
    edges,
    metrics: {
      nodes: graphNodes.length,
      legacyCallable: graphNodes.filter((node) => node.risk === "legacy-callable").length,
      upgradedLinks:
        report.target.chainFamily === "sui"
          ? report.packageLinks.filter((link) => link.status === "upgraded_in_latest").length
          : report.packageLinks.length,
      runtimeUnknown: report.runtimeChecks.filter((check) => check.runtimeStatus === "not_simulated").length
    }
  };
}

function makePackageNode(input: {
  id: string;
  address: string;
  label: string;
  kind: "version" | "dependency";
  version?: string;
  activeStatus?: string;
  x: number;
  y: number;
  callableByAddress: Map<string, number>;
  sensitiveByAddress: Map<string, number>;
  runtimeByAddress: Map<string, number>;
  guardedByAddress: Map<string, number>;
  diffByAddress: Map<string, number>;
  linkByAddress: Map<string, number>;
}): PackageMapNode {
  const callableCount = input.callableByAddress.get(input.id) ?? 0;
  const sensitiveCount = input.sensitiveByAddress.get(input.id) ?? 0;
  const runtimeCount = input.runtimeByAddress.get(input.id) ?? 0;
  const guardedCount = input.guardedByAddress.get(input.id) ?? 0;
  const diffCount = input.diffByAddress.get(input.id) ?? 0;
  const linkCount = input.linkByAddress.get(input.id) ?? 0;
  const load = callableCount + runtimeCount + diffCount + linkCount;
  const risk =
    input.activeStatus === "active"
      ? "current"
      : input.kind === "dependency"
        ? "dependency"
        : guardedCount > 0
          ? "guarded"
          : callableCount > 0 || sensitiveCount > 0
            ? "legacy-callable"
            : "unknown";

  return {
    id: input.id,
    address: input.address,
    label: input.label,
    kind: input.kind,
    version: input.version,
    activeStatus: input.activeStatus,
    x: input.x,
    y: input.y,
    r: Math.min(42, 22 + Math.sqrt(load) * 2.4),
    callableCount,
    sensitiveCount,
    runtimeCount,
    guardedCount,
    diffCount,
    linkCount,
    risk
  };
}

function countByAddress<T>(items: T[], getAddress: (item: T) => string | undefined, predicate?: (item: T) => boolean) {
  const counts = new Map<string, number>();
  for (const item of items) {
    if (predicate && !predicate(item)) continue;
    increment(counts, getAddress(item));
  }
  return counts;
}

function increment(counts: Map<string, number>, address: string | undefined) {
  const id = normalizeAddress(address);
  if (!id) return;
  counts.set(id, (counts.get(id) ?? 0) + 1);
}

function normalizeAddress(address: string | undefined): string {
  return address?.toLowerCase() ?? "";
}

function numericVersion(identifier: string): number {
  const match = identifier.match(/\d+/);
  return match ? Number(match[0]) : Number.MAX_SAFE_INTEGER;
}

function displayVersion(identifier: string): string {
  const match = identifier.match(/\d+/);
  return match ? match[0] : identifier;
}

function shortAddress(address: string): string {
  if (address.length <= 14) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function riskLabel(risk: PackageMapRisk): string {
  switch (risk) {
    case "current":
      return "current";
    case "legacy-callable":
      return "legacy callable";
    case "guarded":
      return "runtime guarded";
    case "dependency":
      return "dependency";
    default:
      return "unknown";
  }
}

function riskBadgeClass(risk: PackageMapRisk): Severity {
  if (risk === "legacy-callable") return "medium";
  if (risk === "guarded") return "low";
  if (risk === "current") return "info";
  return "low";
}

function SummaryList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <>
      <h3>{title}</h3>
      <ul>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </>
  );
}

function ReportTable({ title, headers, rows }: { title: string; headers: string[]; rows: string[][] }) {
  return (
    <section className="section">
      <h2>{title}</h2>
      <div className="table-wrap">
        <table className="report-table">
          <thead>
            <tr>
              {headers.map((header) => (
                <th key={header}>{header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={`${title}-${index}`}>
                {row.map((cell, cellIndex) => (
                  <td className={cell.startsWith("0x") ? "mono" : undefined} key={`${cell}-${cellIndex}`}>
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
            {rows.length === 0 ? (
              <tr>
                <td colSpan={headers.length}>No data available.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
