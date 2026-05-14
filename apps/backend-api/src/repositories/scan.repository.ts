import { prisma } from '../config/database';
import { Scan, Prisma } from '@prisma/client';

export class ScanRepository {
  /**
   * Persists a completed scan result to the database.
   * Links the scan to a specific user for history tracking.
   */
  public async createScan(data: Prisma.ScanUncheckedCreateInput): Promise<Scan> {
    return prisma.scan.create({
      data,
    });
  }

  /**
   * Retrieves all scan history for a specific user, ordered by most recent.
   * @param userId - The UUID of the authenticated user
   */
  public async findHistoryByUserId(userId: string): Promise<Scan[]> {
    return prisma.scan.findMany({
      where: { userId },
      orderBy: { scannedAt: 'desc' },
    });
  }

  /**
   * SCALABILITY: Deletes a scan from history.
   */
  public async deleteScan(id: string, userId: string): Promise<Scan> {
    return prisma.scan.delete({
      where: { id, userId },
    });
  }
}
