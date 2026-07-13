import { NextResponse } from "next/server";
import { scans } from "../../store";

export const runtime = "nodejs";

export async function GET(_request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const scan = scans.get(scanId);
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  return NextResponse.json({ id: scan.id, status: scan.status, stages: scan.stages, error: scan.error });
}
