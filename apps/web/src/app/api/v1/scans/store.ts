import type { ScanReport, ScanStage } from "@packsight/report-schema";

export interface ScanRecord {
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  stages: Array<{ stage: ScanStage; label: string; at: string }>;
  report?: ScanReport;
  error?: string;
}

const globalStore = globalThis as typeof globalThis & {
  __packsightScans?: Map<string, ScanRecord>;
  __packsightIdempotency?: Map<string, string>;
};

export const scans = globalStore.__packsightScans ?? new Map<string, ScanRecord>();
export const idempotencyIndex = globalStore.__packsightIdempotency ?? new Map<string, string>();

globalStore.__packsightScans = scans;
globalStore.__packsightIdempotency = idempotencyIndex;
