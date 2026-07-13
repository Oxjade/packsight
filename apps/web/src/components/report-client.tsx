"use client";

import { useMemo, useState } from "react";
import type { ScanReport, Severity } from "@packsight/report-schema";
import { Download, FileJson, FileText } from "lucide-react";

const severityFilters: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];

export function ReportClient({ report }: { report: ScanReport }) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const packageLinks = report.packageLinks ?? [];
  const runtimeChecks = report.runtimeChecks ?? [];
  const findings = useMemo(
    () => report.findings.filter((finding) => severity === "all" || finding.severity === severity),
    [report.findings, severity]
  );

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
            {report.target.chainFamily} · {report.target.network} · {report.target.address}
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
          <table>
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
        title="Legacy-to-upgrade function diff"
        headers={["Function", "Status", "Access", "Legacy package", "Compared package", "Sensitive"]}
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
        title="Package linkage"
        headers={["Original", "Scanned resolution", "Latest resolution", "Status", "Relationship"]}
        rows={packageLinks.map((link) => [
          link.originalPackageId,
          `${link.resolvedPackageId}${link.resolvedVersion ? ` @ v${link.resolvedVersion}` : ""}`,
          link.latestResolvedPackageId
            ? `${link.latestResolvedPackageId}${link.latestResolvedVersion ? ` @ v${link.latestResolvedVersion}` : ""}`
            : "not found",
          link.status,
          link.relationship
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
  const target = [report.target.chainFamily, report.target.network, report.target.address].filter(Boolean).join(" / ");
  return [
    `# PackSight Security Hygiene Report`,
    "",
    `- Scan ID: ${report.id}`,
    `- Target: ${target}`,
    `- Status: ${report.status}`,
    `- Score: ${report.score}/100`,
    `- Grade: ${report.grade}`,
    `- Started: ${report.startedAt}`,
    report.completedAt ? `- Completed: ${report.completedAt}` : undefined,
    report.scanPoint?.chainCheckpoint ? `- Chain checkpoint: ${report.scanPoint.chainCheckpoint}` : undefined,
    report.scanPoint?.blockNumber ? `- Block number: ${report.scanPoint.blockNumber}` : undefined,
    report.scanPoint?.slot ? `- Slot: ${report.scanPoint.slot}` : undefined,
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
    "## Package Linkage",
    "",
    report.packageLinks.length > 0
      ? markdownTable(
          ["Original", "Scanned resolution", "Latest resolution", "Status", "Relationship"],
          report.packageLinks.map((link) => [
            link.originalPackageId,
            `${link.resolvedPackageId}${link.resolvedVersion ? ` @ v${link.resolvedVersion}` : ""}`,
            link.latestResolvedPackageId
              ? `${link.latestResolvedPackageId}${link.latestResolvedVersion ? ` @ v${link.latestResolvedVersion}` : ""}`
              : "not found",
            link.status,
            link.relationship
          ])
        )
      : "No package linkage data available.",
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
        <table>
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
