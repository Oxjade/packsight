#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { runScan } from "@packsight/scanner-core";
import type { Severity } from "@packsight/report-schema";

const rawArgs = process.argv.slice(2);
const args = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;

if (args.length === 0 || args.includes("--help")) {
  printHelp();
  process.exit(0);
}

const [command, subcommand, target] = args;

if (command !== "scan" || !["sui", "solana", "evm"].includes(subcommand ?? "") || !target) {
  printHelp();
  process.exit(1);
}

const options = parseOptions(args.slice(3));
const chainFamily = subcommand as "sui" | "solana" | "evm";
const report = await runScan({
  id: crypto.randomUUID(),
  request: {
    targetType: "chain_address",
    chainFamily,
    network: options.network ?? "mainnet",
    address: target,
    repositoryUrl: options.repo,
    commitSha: options.commit,
    sourcePath: options.source,
    customRpcUrl: options.rpc,
    customGraphqlUrl: options.graphql
  }
});

const output = JSON.stringify(report, null, 2);
if (options.output) {
  await writeFile(options.output, `${output}\n`);
} else {
  process.stdout.write(`${output}\n`);
}

if (options.failOn && shouldFail(report.findings.map((finding) => finding.severity), options.failOn as Severity)) {
  process.exit(2);
}

function parseOptions(raw: string[]): Record<string, string | undefined> {
  const parsed: Record<string, string | undefined> = {};
  for (let index = 0; index < raw.length; index += 1) {
    const item = raw[index];
    if (!item?.startsWith("--")) {
      continue;
    }
    const key = item.slice(2).replace(/-([a-z])/g, (_, letter: string) => letter.toUpperCase());
    parsed[key] = raw[index + 1];
    index += 1;
  }
  return parsed;
}

function shouldFail(severities: Severity[], threshold: Severity): boolean {
  const rank: Record<Severity, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  };
  return severities.some((severity) => rank[severity] >= rank[threshold]);
}

function printHelp() {
  process.stdout.write(`packsight

Usage:
  packsight scan sui <package-id> --network mainnet --source fixtures/sui/legacy-package
  packsight scan solana <program-id> --network mainnet-beta --rpc https://...
  packsight scan evm <contract-address> --network mainnet --rpc https://...

Options:
  --network <name>     chain network name
  --rpc <url>          custom Solana/EVM JSON-RPC endpoint
  --graphql <url>      custom Sui GraphQL endpoint
  --source <path>      local source path containing source, IDL, or ABI artifacts
  --repo <url>         repository URL metadata
  --commit <sha>       exact source commit
  --output <path>      write JSON report to a file
  --fail-on <level>    info, low, medium, high, critical
`);
}
