import { NextResponse } from "next/server";
import { scans } from "../../store";

export const runtime = "nodejs";

export async function GET(_request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const scan = scans.get(scanId);
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  if (!scan.report) return NextResponse.json({ error: "Report is not ready" }, { status: 425 });
  return NextResponse.json(scan.report);
}
