// SHIVAM WORK AREA
/**
 * apps/backend-api/src/queues/scanProcessor.ts
 */
import { Worker, Job } from 'bullmq';
import { redis } from '../config/redis';
import axios from 'axios';
import prisma from '../config/database';
import { getIO } from '../config/socket';
import { logger } from '../utils/logger';

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || 'http://ai-engine:8000';

export const scanWorker = new Worker(
  'ScanQueue',
  async (job: Job) => {
    const { scanId, type, target } = job.data;
    logger.info('Processing scan job', { scanId, type, target });

    try {
      let response;
      const endpoint = `${AI_ENGINE_URL}/analyze/${type.toLowerCase()}`;
      
      response = await axios.post(endpoint, { target }, { timeout: 30000 });
      const analysis = response.data;

      const updatedScan = await prisma.scan.update({
        where: { id: scanId },
        data: {
          riskScore: analysis.riskScore,
          riskLevel: analysis.riskLevel,
          confidence: analysis.confidence,
          explanation: analysis.explanation,
          rawAiResponse: analysis,
          isProcessed: true,
        },
      });

      // Notify User
      const io = getIO();
      io.to(`user:${updatedScan.userId}`).emit('scan:complete', updatedScan);

      return analysis;
    } catch (err: any) {
      logger.error('Scan processing failed', { scanId, error: err.message });
      throw err;
    }
  },
  {
    connection: redis,
    concurrency: 5,
  }
);
