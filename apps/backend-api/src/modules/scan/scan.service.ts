// SHIVAM WORK AREA
/**
 * apps/backend-api/src/modules/scan/scan.service.ts
 */
import { ScanRepository } from './scan.repository';
import { ScanType } from '@prisma/client';
import { scanQueue } from '../../queues/scanQueue';

export class ScanService {
  private repository: ScanRepository;

  constructor() {
    this.repository = new ScanRepository();
  }

  async initiateUrlScan(url: string, userId: string) {
    const cached = await this.repository.findByTarget(url);
    if (cached) return cached;

    const scan = await this.repository.create({ target: url, type: ScanType.URL, userId });
    await scanQueue.add('processScan', { scanId: scan.id, type: ScanType.URL, target: url });
    
    return scan;
  }

  async initiateAsyncScan(target: string, type: ScanType, userId: string) {
    const scan = await this.repository.create({ target, type, userId });
    await scanQueue.add('processScan', { scanId: scan.id, type, target });
    return scan;
  }

  async getUserScans(userId: string, page: number, limit: number) {
    const skip = (page - 1) * limit;
    return this.repository.findByUser(userId, skip, limit);
  }
}
