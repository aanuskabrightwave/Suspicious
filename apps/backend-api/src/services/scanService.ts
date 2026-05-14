import axios from 'axios';
import { PrismaClient } from '@prisma/client';
import { Queue, Job } from 'bullmq';
import { Redis } from 'ioredis';
import { emitScanCompletion } from '../socket'; // Import socket emitter

const prisma = new PrismaClient();
const redisConnection = new Redis(process.env.REDIS_URL!);

// Define BullMQ Queues
export const scanQueue = new Queue('scan', { connection: redisConnection });

// SHIVAM WORK AREA
export const initiateUrlScan = async (url: string, userId: string, deviceId: string) => {
  // 1. Check cache first (Prisma lookup on Scan table)
  const cachedScan = await prisma.scan.findFirst({
    where: {
      target: url,
      scanType: 'URL',
      createdAt: { gte: new Date(Date.now() - 15 * 60 * 1000) }, // Last 15 mins
    },
    orderBy: { createdAt: 'desc' },
  });

  if (cachedScan && cachedScan.status === 'COMPLETED') {
    console.log(`Returning cached result for URL: ${url}`);
    return cachedScan; // Return cached result
  }

  // 2. Create PENDING scan record
  let scanRecord = await prisma.scan.create({
    data: {
      userId,
      deviceId,
      scanType: 'URL',
      target: url,
      status: 'PENDING',
    },
  });

  // 3. Push job to queue for processing by AI Engine
  await scanQueue.add('url-scan', { scanId: scanRecord.id, url, userId, deviceId });

  return scanRecord; // Return pending record
};

// SHIVAM WORK AREA
export const initiateQrImageScan = async (imageData: string, userId: string, deviceId: string) => {
  // 1. Create PENDING scan record
  const scanRecord = await prisma.scan.create({
     {
      userId,
      deviceId,
      scanType: 'QR', // Could be 'IMAGE_OCR' depending on how you differentiate
      target: imageData, // Store base64 initially, AI engine handles processing
      status: 'PENDING',
    },
  });

// 2. Push job to queue for processing by AI Engine
await scanQueue.add('image-scan', { scanId: scanRecord.id, imageData, userId, deviceId });

return scanRecord; // Return pending record
};

// Worker function to be run separately (could be in another file or triggered differently)
// This simulates the worker pulling from the queue, but in a real setup, you'd have a dedicated worker process.
// For demo purposes within the API service, you might trigger this differently or use BullMQ's built-in worker.

// Example of how a job processor might look (typically in a separate worker file):
/*
import { Worker } from 'bullmq';

const scanWorker = new Worker('scan', async (job: Job) => {
  const { scanId, url, imageData, userId, deviceId } = job.data;

  try {
    let result: ScanResult;

    if (url) {
      // Call AI engine for URL scan
      const aiResponse = await axios.post(`${process.env.AI_ENGINE_URL}/analyze/url`, { url });
      result = aiResponse.data; // Assuming AI returns ScanResult structure
    } else if (imageData) {
      // Call AI engine for Image/QR scan
      const aiResponse = await axios.post(`${process.env.AI_ENGINE_URL}/analyze/image`, { imageData });
      result = aiResponse.data; // Assuming AI returns ScanResult structure
    } else {
      throw new Error("Invalid job data");
    }

    // Update the scan record in the database
    const updatedScan = await prisma.scan.update({
      where: { id: scanId },
       {
        status: 'COMPLETED',
        riskScore: result.riskScore,
        category: result.category,
        explanation: result.explanation,
        completedAt: new Date(),
      },
    });

    // Emit the result via Socket.IO
    emitScanCompletion(userId, updatedScan);

    return updatedScan;

  } catch (error) {
    console.error(`Job ${job.id} failed:`, error);
    // Update scan record as failed
    await prisma.scan.update({
      where: { id: scanId },
       { status: 'FAILED', explanation: (error as Error).message },
    });
    // Optionally notify user via socket about failure
    emitScanCompletion(userId, { id: scanId, status: 'FAILED', explanation: (error as Error).message } as any);
    throw error; // Rethrow to mark job as failed
  }
}, { connection: redisConnection });

// Graceful shutdown
process.on('SIGTERM', async () => {
  await scanWorker.close();
});
*/
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^...... (Truncated due to length) */

// Instead, let's simulate a simple mechanism to trigger the 'worker' logic periodically for demo purposes.
// In a real application, you would run the worker process separately.

setInterval(async () => {
  const pendingJobs = await scanQueue.getWaiting();
  for (const job of pendingJobs) {
    // Simulate fetching the job and processing it
    const jobData = job.data;
    console.log(`Simulating processing of job ${job.id} with `, jobData);

    // Simulate calling the AI engine and updating the DB
    try {
      // Placeholder for actual AI call
      // const aiResponse = await axios.post(`${process.env.AI_ENGINE_URL}/analyze/...`, jobData);
      // const result = aiResponse.data;

      // Simulate a successful result
      const mockRiskScore = Math.random(); // Random score for demo
      const mockCategory = mockRiskScore > 0.7 ? 'HIGH_RISK' : 'LOW_RISK';
      const mockExplanation = `Mock analysis complete for ${jobData.url || 'image'}.`;

      const updatedScan = await prisma.scan.update({
        where: { id: jobData.scanId },
        data: {
          status: 'COMPLETED',
          riskScore: mockRiskScore,
          category: mockCategory,
          explanation: mockExplanation,
          completedAt: new Date(),
        },
      });

      // Emit the result via Socket.IO
      emitScanCompletion(jobData.userId, updatedScan);
      console.log(`Simulated completion for scan ${jobData.scanId}`);

      // Remove the simulated job from the queue (in a real worker, job.complete() is called)
      await job.remove();

    } catch (error) {
      console.error(`Simulated job ${job.id} failed:`, error);
      await prisma.scan.update({
        where: { id: jobData.scanId },
        data: { status: 'FAILED', explanation: (error as Error).message },
      });
      emitScanCompletion(jobData.userId, { id: jobData.scanId, status: 'FAILED', explanation: (error as Error).message } as any);
      await job.remove(); // Remove failed job simulation
    }
  }
}, 5000); // Check every 5 seconds for demo

console.log("Simulated scan worker started.");