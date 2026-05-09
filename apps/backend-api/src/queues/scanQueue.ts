// SHIVAM WORK AREA
/**
 * apps/backend-api/src/queues/scanQueue.ts
 */
import { Queue } from 'bullmq';
import { redis } from '../config/redis';

export const scanQueue = new Queue('ScanQueue', {
  connection: redis,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1000,
    },
  },
});