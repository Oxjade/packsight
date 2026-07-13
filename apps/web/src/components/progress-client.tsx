"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { CheckCircle2, CircleDashed, XCircle } from "lucide-react";
import { progressStages, stageLabels } from "@packsight/shared";

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "/api";

interface StatusResponse {
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  stages: Array<{ stage: string; label: string; at: string }>;
  error?: string;
}

export function ProgressClient({ scanId }: { scanId: string }) {
  const [status, setStatus] = useState<StatusResponse | null>(null);

  useEffect(() => {
    let active = true;
    const poll = async () => {
      const response = await fetch(`${apiUrl}/v1/scans/${scanId}/status`, { cache: "no-store" });
      const body = (await response.json()) as StatusResponse;
      if (active) setStatus(body);
    };

    void poll();
    const interval = window.setInterval(() => {
      void poll();
    }, 1200);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [scanId]);

  const completedStages = new Set(status?.stages.map((stage) => stage.stage) ?? []);

  return (
    <section className="section">
      <div className="progress-list">
        {progressStages.map((stage) => {
          const done = completedStages.has(stage);
          return (
            <div className={`progress-step ${done ? "done" : ""}`} key={stage}>
              <span>{stageLabels[stage]}</span>
              {done ? <CheckCircle2 size={20} aria-label="Complete" /> : <CircleDashed size={20} aria-label="Pending" />}
            </div>
          );
        })}
      </div>
      {status?.status === "failed" ? (
        <p className="error-text">
          <XCircle size={18} aria-hidden="true" /> {status.error ?? "The scan failed."}
        </p>
      ) : null}
      {status?.status === "completed" ? (
        <p>
          <Link className="button" href={`/scans/${scanId}/report`}>
            Open report
          </Link>
        </p>
      ) : null}
    </section>
  );
}
