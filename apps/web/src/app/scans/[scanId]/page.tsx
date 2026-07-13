import { ProgressClient } from "@/components/progress-client";

export default async function ScanProgressPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  return (
    <div className="page">
      <section className="report-band">
        <h1>Scan progress</h1>
        <p>
          packsight is collecting chain metadata, resolving source coverage and generating a report. Stages update as
          the API records progress.
        </p>
      </section>
      <ProgressClient scanId={scanId} />
    </div>
  );
}
