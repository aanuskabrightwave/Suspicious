// apps/backend-api/src/queues/scanQueue.ts
import { Queue } from 'bullmq';
import { getRedisClient } from '../config/redis';

export const scanQueue = new Queue('ScanQueue', {
  connection: getRedisClient(),
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1000,
    },
  },
});

export async function closeScanQueue(): Promise<void> {
  await scanQueue.close();
}
