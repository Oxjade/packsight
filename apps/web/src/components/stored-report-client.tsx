"use client";

import { useEffect, useState } from "react";
import type { ScanReport } from "@packsight/report-schema";
import { ReportClient } from "@/components/report-client";

export function StoredReportClient({ scanId }: { scanId: string }) {
  const [report, setReport] = useState<ScanReport | null>(null);

  useEffect(() => {
    try {
      const stored = window.sessionStorage.getItem(`packsight-report:${scanId}`);
      if (!stored) return;
      setReport(JSON.parse(stored) as ScanReport);
    } catch {
      window.sessionStorage.removeItem(`packsight-report:${scanId}`);
    }
  }, [scanId]);

  if (report) return <ReportClient report={report} />;

  return (
    <div className="page">
      <section className="report-band">
        <h1>Report unavailable</h1>
        <p>The scan report is not ready, expired from this browser session, or the deployment could not find that scan.</p>
      </section>
    </div>
  );
}
