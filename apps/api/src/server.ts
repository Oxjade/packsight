import cors from "@fastify/cors";
import Fastify from "fastify";
import type { ScanReport, ScanStage } from "@packsight/report-schema";
import { ruleDefinitions } from "@packsight/rule-engine";
import { runScan } from "@packsight/scanner-core";
import { createScanRequestSchema, progressStages, stageLabels } from "@packsight/shared";

interface ScanRecord {
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  stages: Array<{ stage: ScanStage; label: string; at: string }>;
  report?: ScanReport;
  error?: string;
}

const scans = new Map<string, ScanRecord>();
const idempotencyIndex = new Map<string, string>();

export function buildServer() {
  const app = Fastify({ logger: true });

  app.register(cors, { origin: true });

  app.get("/health", async () => ({ ok: true }));
  app.get("/ready", async () => ({ ok: true, scanner: "sui" }));

  app.post("/v1/scans", async (request, reply) => {
    const parsed = createScanRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid scan request", issues: parsed.error.issues });
    }

    const idempotencyKey = request.headers["idempotency-key"];
    if (typeof idempotencyKey === "string" && idempotencyIndex.has(idempotencyKey)) {
      const existingId = idempotencyIndex.get(idempotencyKey);
      return reply.status(202).send({ scanId: existingId, statusUrl: `/v1/scans/${existingId}/status` });
    }

    const scanId = crypto.randomUUID();
    scans.set(scanId, { id: scanId, status: "queued", stages: [] });
    if (typeof idempotencyKey === "string") idempotencyIndex.set(idempotencyKey, scanId);

    void runScanInBackground(scanId, parsed.data);
    return reply.status(202).send({ scanId, statusUrl: `/v1/scans/${scanId}/status` });
  });

  app.get("/v1/scans/:scanId", async (request, reply) => {
    const scan = scans.get((request.params as { scanId: string }).scanId);
    if (!scan) return reply.status(404).send({ error: "Scan not found" });
    return scan;
  });

  app.get("/v1/scans/:scanId/status", async (request, reply) => {
    const scan = scans.get((request.params as { scanId: string }).scanId);
    if (!scan) return reply.status(404).send({ error: "Scan not found" });
    return { id: scan.id, status: scan.status, stages: scan.stages, error: scan.error };
  });

  app.get("/v1/scans/:scanId/report", async (request, reply) => {
    const scan = scans.get((request.params as { scanId: string }).scanId);
    if (!scan) return reply.status(404).send({ error: "Scan not found" });
    if (!scan.report) return reply.status(425).send({ error: "Report is not ready" });
    return scan.report;
  });

  app.get("/v1/scans/:scanId/findings", async (request, reply) => {
    const scan = scans.get((request.params as { scanId: string }).scanId);
    if (!scan?.report) return reply.status(scan ? 425 : 404).send({ error: scan ? "Report is not ready" : "Scan not found" });
    return scan.report.findings;
  });

  app.get("/v1/scans/:scanId/dependencies", async (request, reply) => {
    const scan = scans.get((request.params as { scanId: string }).scanId);
    if (!scan?.report) return reply.status(scan ? 425 : 404).send({ error: scan ? "Report is not ready" : "Scan not found" });
    return scan.report.dependencies;
  });

  app.get("/v1/scans/:scanId/versions", async (request, reply) => {
    const scan = scans.get((request.params as { scanId: string }).scanId);
    if (!scan?.report) return reply.status(scan ? 425 : 404).send({ error: scan ? "Report is not ready" : "Scan not found" });
    return scan.report.versions;
  });

  app.post("/v1/scans/:scanId/rescan", async (request, reply) => {
    return reply.status(501).send({ error: "Rescan persistence will be enabled after database-backed scan records are wired." });
  });

  app.post("/v1/scans/:scanId/export", async (request, reply) => {
    const scan = scans.get((request.params as { scanId: string }).scanId);
    if (!scan?.report) return reply.status(scan ? 425 : 404).send({ error: scan ? "Report is not ready" : "Scan not found" });
    return { format: "json", report: scan.report };
  });

  app.get("/v1/rules", async () => ruleDefinitions);
  app.get("/v1/rules/:ruleId", async (request, reply) => {
    const rule = ruleDefinitions.find((definition) => definition.id === (request.params as { ruleId: string }).ruleId);
    if (!rule) return reply.status(404).send({ error: "Rule not found" });
    return rule;
  });

  return app;
}

async function runScanInBackground(scanId: string, request: ReturnType<typeof createScanRequestSchema.parse>) {
  const scan = scans.get(scanId);
  if (!scan) return;

  scan.status = "running";

  try {
    const report = await runScan({
      id: scanId,
      request,
      onStage(stage) {
        if (progressStages.includes(stage as (typeof progressStages)[number])) {
          scan.stages.push({
            stage,
            label: stageLabels[stage as (typeof progressStages)[number]],
            at: new Date().toISOString()
          });
        }
      }
    });
    scan.report = report;
    scan.status = "completed";
  } catch (error) {
    scan.status = "failed";
    scan.error = error instanceof Error ? error.message : "Unknown scan failure";
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.API_PORT ?? 4000);
  const app = buildServer();
  await app.listen({ host: "0.0.0.0", port });
}
