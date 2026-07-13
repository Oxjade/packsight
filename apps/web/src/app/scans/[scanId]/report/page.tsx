import { ReportClient } from "@/components/report-client";
import type { ScanReport } from "@packsight/report-schema";

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

export default async function ReportPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const response = await fetch(`${apiUrl}/v1/scans/${scanId}/report`, { cache: "no-store" });

  if (!response.ok) {
    return (
      <div className="page">
        <section className="report-band">
          <h1>Report unavailable</h1>
          <p>The scan report is not ready or the API could not find that scan.</p>
        </section>
      </div>
    );
  }

  const report = (await response.json()) as ScanReport;
  return <ReportClient report={report} />;
}
