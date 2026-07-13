import { NextResponse } from "next/server";
import { runScan } from "@packsight/scanner-core";
import { createScanRequestSchema, progressStages, stageLabels } from "@packsight/shared";
import { idempotencyIndex, scans } from "./store";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(request: Request) {
  const parsed = createScanRequestSchema.safeParse(await request.json());
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid scan request", issues: parsed.error.issues }, { status: 400 });
  }

  const idempotencyKey = request.headers.get("idempotency-key");
  if (idempotencyKey && idempotencyIndex.has(idempotencyKey)) {
    const existingId = idempotencyIndex.get(idempotencyKey);
    return NextResponse.json({ scanId: existingId, statusUrl: `/api/v1/scans/${existingId}/status` }, { status: 202 });
  }

  const scanId = crypto.randomUUID();
  scans.set(scanId, { id: scanId, status: "running", stages: [] });
  if (idempotencyKey) idempotencyIndex.set(idempotencyKey, scanId);

  const scan = scans.get(scanId);
  if (!scan) {
    return NextResponse.json({ error: "Scan could not be created" }, { status: 500 });
  }

  try {
    scan.report = await runScan({
      id: scanId,
      request: parsed.data,
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
    scan.status = "completed";
    return NextResponse.json({ scanId, statusUrl: `/api/v1/scans/${scanId}/status`, report: scan.report }, { status: 202 });
  } catch (error) {
    scan.status = "failed";
    scan.error = error instanceof Error ? error.message : "Unknown scan failure";
    return NextResponse.json({ scanId, error: scan.error }, { status: 500 });
  }
}
