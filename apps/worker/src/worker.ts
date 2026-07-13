import { Worker } from "bullmq";
import pino from "pino";
import { runScan } from "@packsight/scanner-core";

const logger = pino({ name: "packsight-worker" });
const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379";
const parsedRedisUrl = new URL(redisUrl);
const connection = {
  host: parsedRedisUrl.hostname,
  port: Number(parsedRedisUrl.port || 6379),
  maxRetriesPerRequest: null
};

new Worker(
  "scan-jobs",
  async (job) => {
    logger.info({ jobId: job.id }, "running scan job");
    return runScan({
      id: String(job.id),
      request: job.data,
      onStage: async (stage) => {
        await job.updateProgress({ stage });
      }
    });
  },
  { connection }
);

logger.info({ redisUrl }, "packsight worker ready");
