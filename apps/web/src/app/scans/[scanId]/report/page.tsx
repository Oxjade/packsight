import { ReportClient } from "@/components/report-client";
import { StoredReportClient } from "@/components/stored-report-client";
import type { ScanReport } from "@packsight/report-schema";

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

export default async function ReportPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const report = await fetchReport(scanId);
  return report ? <ReportClient report={report} /> : <StoredReportClient scanId={scanId} />;
}

function apiEndpoint(path: string): string {
  if (process.env.NEXT_PUBLIC_API_URL) return `${apiUrl}${path}`;
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}/api${path}`;
  return `http://localhost:3000/api${path}`;
}

async function fetchReport(scanId: string): Promise<ScanReport | null> {
  try {
    const response = await fetch(apiEndpoint(`/v1/scans/${scanId}/report`), { cache: "no-store" });
    if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) {
      return null;
    }
    return (await response.json()) as ScanReport;
  } catch {
    return null;
  }
}
