// SHIVAM WORK AREA
/**
 * apps/backend-api/src/modules/scan/scan.repository.ts
 */
import prisma from '../../config/database';
import { ScanType } from '@prisma/client';

export class ScanRepository {
  async findByTarget(target: string) {
    return prisma.scan.findFirst({
      where: { target, isProcessed: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async create(data: { target: string; type: ScanType; userId: string }) {
    return prisma.scan.create({
      data: {
        ...data,
        isProcessed: false,
      },
    });
  }

  async update(id: string, data: any) {
    return prisma.scan.update({
      where: { id },
      data: {
        ...data,
        isProcessed: true,
      },
    });
  }

  async findByUser(userId: string, skip: number, take: number) {
    return prisma.scan.findMany({
      where: { userId },
      skip,
      take,
      orderBy: { createdAt: 'desc' },
    });
  }
}
