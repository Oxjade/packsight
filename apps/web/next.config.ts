import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: [
    "@packsight/adapter-evm",
    "@packsight/adapter-solana",
    "@packsight/adapter-sui",
    "@packsight/dependency-scanner",
    "@packsight/move-analyzer",
    "@packsight/report-schema",
    "@packsight/rule-engine",
    "@packsight/scanner-core",
    "@packsight/shared"
  ]
};

export default nextConfig;
