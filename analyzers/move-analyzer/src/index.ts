import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import type { CallableSurface, Evidence } from "@packsight/report-schema";

export interface MoveFunctionAnalysis {
  moduleName: string;
  functionName: string;
  visibility: string;
  entry: boolean;
  deprecated: boolean | "unknown";
  mutatesState: boolean | "unknown";
  valueSensitive: boolean | "unknown";
  hasVersionGate: boolean;
  lineStart: number;
  lineEnd: number;
  file: string;
}

export interface MoveSourceAnalysis {
  callableSurface: CallableSurface[];
  functions: MoveFunctionAnalysis[];
  evidence: Evidence[];
  sourceFiles: string[];
  oldPackageReferences: string[];
  hasVersionState: boolean;
}

const sensitiveTerms = /\b(treasury|vault|reward|admin|capability|cap|mint|burn|withdraw|claim|transfer|upgrade|authority|owner)\b/i;
const mutationTerms = /\b(&mut|transfer::|coin::|balance::|table::|dynamic_field::|object::delete|move_to|move_from)\b/;
const deprecationTerms = /\b(deprecated|legacy|obsolete|remove-after|remove after)\b/i;
const versionStateTerms = /\b(version|current_version|package_version|schema_version)\b/i;
const versionGateTerms = /\b(assert!|abort|ensure!|ENOT_CURRENT|E_VERSION|current_version|package_version|schema_version)\b/i;
const packageIdPattern = /0x[a-fA-F0-9]{32,64}/g;

export async function analyzeMoveSource(rootDir: string): Promise<MoveSourceAnalysis> {
  const sourceRoot = join(rootDir, "sources");
  const files = await collectMoveFiles(sourceRoot);
  const functions: MoveFunctionAnalysis[] = [];
  const evidence: Evidence[] = [];
  const oldPackageReferences = new Set<string>();
  let hasVersionState = false;

  for (const filePath of files) {
    const contents = await readFile(filePath, "utf8");
    const file = relative(rootDir, filePath);
    for (const match of contents.matchAll(packageIdPattern)) {
      oldPackageReferences.add(match[0]);
    }
    hasVersionState ||= versionStateTerms.test(contents);
    functions.push(...parseMoveFunctions(contents, file));
  }

  const callableSurface = functions.map((fn): CallableSurface => ({
    name: `${fn.moduleName}::${fn.functionName}`,
    module: fn.moduleName,
    visibility: fn.entry ? "entry" : fn.visibility,
    deprecated: fn.deprecated,
    reachable: fn.visibility.includes("public") || fn.entry ? "unknown" : false,
    mutatesState: fn.mutatesState,
    valueSensitive: fn.valueSensitive
  }));

  if (files.length === 0) {
    evidence.push({
      type: "missing_information",
      value: "No Move source files found under sources/"
    });
  }

  return {
    callableSurface,
    functions,
    evidence,
    sourceFiles: files.map((filePath) => relative(rootDir, filePath)),
    oldPackageReferences: [...oldPackageReferences],
    hasVersionState
  };
}

export function parseMoveFunctions(contents: string, file: string): MoveFunctionAnalysis[] {
  const lines = contents.split(/\r?\n/);
  const moduleName = parseModuleName(contents) ?? "unknown";
  const functions: MoveFunctionAnalysis[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const signature = /\b(public(?:\([^)]+\))?\s+)?(entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\b/.exec(line);
    if (!signature) {
      continue;
    }

    const priorComments = lines.slice(Math.max(0, index - 4), index).join("\n");
    const body = collectFunctionBody(lines, index);
    const visibility = signature[1]?.trim() ?? "private";
    const entry = Boolean(signature[2]) || /\bentry\s+fun\b/.test(line);
    const deprecated = deprecationTerms.test(priorComments) || deprecationTerms.test(line);
    const mutatesState = mutationTerms.test(body) || /&mut/.test(line);
    const normalizedFunctionName = (signature[3] ?? "").replace(/_/g, " ");
    const valueSensitive = sensitiveTerms.test(normalizedFunctionName) || sensitiveTerms.test(body);
    const hasVersionGate = versionGateTerms.test(body) && /\b(assert!|abort|ensure!)\b/.test(body);

    functions.push({
      moduleName,
      functionName: signature[3] ?? "unknown",
      visibility,
      entry,
      deprecated: deprecated ? true : "unknown",
      mutatesState: mutatesState ? true : "unknown",
      valueSensitive: valueSensitive ? true : "unknown",
      hasVersionGate,
      lineStart: index + 1,
      lineEnd: index + body.split(/\r?\n/).length,
      file
    });
  }

  return functions;
}

function parseModuleName(contents: string): string | undefined {
  return /\bmodule\s+[A-Za-z0-9_]+::([A-Za-z0-9_]+)/.exec(contents)?.[1];
}

function collectFunctionBody(lines: string[], start: number): string {
  const body: string[] = [];
  let depth = 0;
  let opened = false;

  for (let index = start; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    body.push(line);
    for (const char of line) {
      if (char === "{") {
        opened = true;
        depth += 1;
      } else if (char === "}") {
        depth -= 1;
      }
    }
    if (opened && depth <= 0) {
      break;
    }
  }

  return body.join("\n");
}

async function collectMoveFiles(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    const nested = await Promise.all(
      entries.map(async (entry) => {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          return collectMoveFiles(fullPath);
        }
        return entry.isFile() && entry.name.endsWith(".move") ? [fullPath] : [];
      })
    );
    return nested.flat();
  } catch {
    return [];
  }
}
