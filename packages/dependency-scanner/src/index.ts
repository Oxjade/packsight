import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import type { DependencyRecord, Evidence, SecurityFinding } from "@packsight/report-schema";

export interface SourceFileMap {
  [path: string]: string;
}

export interface DependencyScanResult {
  dependencies: DependencyRecord[];
  findings: SecurityFinding[];
  evidence: Evidence[];
  hasMoveManifest: boolean;
  hasMoveLock: boolean;
}

export interface MoveDependencyScanResult {
  dependencies: DependencyRecord[];
  findings: SecurityFinding[];
  evidence: Evidence[];
  lockfilePresent: boolean;
}

const moveDependencyHeader = /^\s*\[dependencies\.([^\]]+)\]\s*$/;
const gitLine = /^\s*git\s*=\s*"([^"]+)"/;
const revLine = /^\s*(rev|commit)\s*=\s*"([^"]+)"/;
const branchLine = /^\s*branch\s*=\s*"([^"]+)"/;

export async function scanMoveDependencies(rootDir: string): Promise<MoveDependencyScanResult> {
  const files = await collectKnownFiles(rootDir, new Set(["Move.toml", "Move.lock", "Published.toml"]));
  const sourceFiles = Object.fromEntries(files.map((file) => [relative(rootDir, file.path), file.content]));
  const result = scanSourceFiles(sourceFiles);

  return {
    dependencies: result.dependencies,
    findings: result.findings,
    evidence: result.evidence,
    lockfilePresent: result.hasMoveLock
  };
}

export function scanSourceFiles(files: SourceFileMap): DependencyScanResult {
  const dependencies: DependencyRecord[] = [];
  const findings: SecurityFinding[] = [];
  const evidence: Evidence[] = [];
  const paths = Object.keys(files);
  const hasMoveManifest = paths.some((path) => basename(path) === "Move.toml");
  const hasMoveLock = paths.some((path) => basename(path) === "Move.lock");

  for (const path of paths) {
    const name = basename(path);
    if (name === "Move.toml" || name === "Move.lock" || name === "Published.toml") {
      evidence.push({
        type: "source_file",
        value: path,
        file: path,
        source: name === "Move.lock" ? "lockfile" : "manifest"
      });
    }
  }

  if (hasMoveManifest && !hasMoveLock) {
    findings.push({
      ruleId: "SUI-DEPS-001",
      title: "Move.lock missing",
      description: "A Move.toml file was supplied without a matching Move.lock file.",
      severity: "low",
      confidence: "confirmed",
      status: "open",
      chainFamily: "sui",
      evidence: [{ type: "manifest", value: "Move.toml", source: "manifest" }],
      affectedComponents: ["Move.toml"],
      impact: "Dependency resolution may be non-reproducible across machines or future scans.",
      recommendation: "Commit Move.lock for deployed Move packages and scan the exact committed lockfile."
    });
  }

  for (const [path, content] of Object.entries(files)) {
    if (basename(path) === "Move.toml") {
      dependencies.push(...parseMoveTomlDependencies(path, content, findings));
    }

    if (basename(path) === "package.json") {
      dependencies.push(...parsePackageJsonDependencies(path, content));
    }
  }

  return { dependencies, findings, evidence, hasMoveManifest, hasMoveLock };
}

function parseMoveTomlDependencies(path: string, content: string, findings: SecurityFinding[]): DependencyRecord[] {
  const records: DependencyRecord[] = [];
  const lines = content.split(/\r?\n/);
  let currentName: string | null = null;
  let currentGit: string | undefined;
  let currentRevision: string | undefined;
  let currentBranch: string | undefined;

  const flush = (): void => {
    if (!currentName) return;

    if (currentGit) {
      records.push({
        ecosystem: "move",
        name: currentName,
        requestedVersion: currentRevision ?? currentBranch,
        source: currentGit,
        direct: true,
        deprecated: "unknown",
        yanked: "unknown",
        vulnerable: "unknown",
        advisories: []
      });

      if (!currentRevision || currentBranch) {
        findings.push({
          ruleId: "SUI-DEPS-002",
          title: "Mutable Git dependency",
          description: currentBranch
            ? `Move dependency ${currentName} is pinned to branch ${currentBranch}, which can move over time.`
            : `Move dependency ${currentName} uses Git without an immutable revision pin.`,
          severity: "low",
          confidence: "confirmed",
          status: "open",
          chainFamily: "sui",
          evidence: [
            {
              type: "manifest_dependency",
              value: `${currentName} ${currentGit}`,
              file: path,
              source: "manifest"
            }
          ],
          affectedComponents: [currentName],
          impact: "Future dependency resolution may select different source code than the code reviewed today.",
          recommendation: "Pin the dependency to an immutable commit revision and keep Move.lock tracked."
        });
      }
    }

    currentName = null;
    currentGit = undefined;
    currentRevision = undefined;
    currentBranch = undefined;
  };

  for (const line of lines) {
    const header = line.match(moveDependencyHeader);
    if (header?.[1]) {
      flush();
      currentName = header[1].trim();
      continue;
    }

    if (!currentName) continue;

    const git = line.match(gitLine);
    if (git?.[1]) currentGit = git[1];

    const rev = line.match(revLine);
    if (rev?.[2]) currentRevision = rev[2];

    const branch = line.match(branchLine);
    if (branch?.[2]) currentBranch = branch[2];
  }

  flush();
  return records;
}

function parsePackageJsonDependencies(path: string, content: string): DependencyRecord[] {
  try {
    const parsed = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };

    const directDependencies = Object.entries(parsed.dependencies ?? {}).map(([name, requestedVersion]) =>
      npmRecord(name, requestedVersion, true, path)
    );
    const devDependencies = Object.entries(parsed.devDependencies ?? {}).map(([name, requestedVersion]) =>
      npmRecord(name, requestedVersion, true, path)
    );

    return [...directDependencies, ...devDependencies];
  } catch {
    return [];
  }
}

function npmRecord(name: string, requestedVersion: string, direct: boolean, source: string): DependencyRecord {
  return {
    ecosystem: "npm",
    name,
    requestedVersion,
    source,
    direct,
    deprecated: "unknown",
    yanked: "unknown",
    vulnerable: "unknown",
    advisories: []
  };
}

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

export async function queryOsv(dependencies: DependencyRecord[]): Promise<DependencyRecord[]> {
  const queries = dependencies
    .filter((dependency) => dependency.resolvedVersion)
    .map((dependency) => ({
      package: { name: dependency.name, ecosystem: osvEcosystem(dependency.ecosystem) },
      version: dependency.resolvedVersion
    }));

  if (queries.length === 0) return dependencies;

  const response = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ queries })
  });

  if (!response.ok) return dependencies;

  const body = (await response.json()) as {
    results?: Array<{ vulns?: Array<{ id: string; summary?: string; database_specific?: { severity?: string } }> }>;
  };

  let resultIndex = 0;
  return dependencies.map((dependency) => {
    if (!dependency.resolvedVersion) return dependency;

    const vulns = body.results?.[resultIndex]?.vulns ?? [];
    resultIndex += 1;
    return {
      ...dependency,
      vulnerable: vulns.length > 0 ? true : dependency.vulnerable,
      advisories: [
        ...dependency.advisories,
        ...vulns.map((vuln) => ({
          id: vuln.id,
          source: "OSV",
          url: `https://osv.dev/vulnerability/${vuln.id}`,
          severity: vuln.database_specific?.severity,
          summary: vuln.summary
        }))
      ]
    };
  });
}

function osvEcosystem(ecosystem: DependencyRecord["ecosystem"]): string {
  if (ecosystem === "npm") return "npm";
  if (ecosystem === "cargo") return "crates.io";
  return ecosystem;
}

async function collectKnownFiles(rootDir: string, basenames: Set<string>): Promise<Array<{ path: string; content: string }>> {
  const files = await collectFiles(rootDir);
  const matched = files.filter((path) => basenames.has(basename(path)));
  return Promise.all(matched.map(async (path) => ({ path, content: await readFile(path, "utf8") })));
}

async function collectFiles(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    const nested = await Promise.all(
      entries.map(async (entry) => {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) return collectFiles(fullPath);
        return entry.isFile() ? [fullPath] : [];
      })
    );
    return nested.flat();
  } catch {
    return [];
  }
}
