import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@packsight/report-schema", "@packsight/rule-engine", "@packsight/shared"]
};

export default nextConfig;
