// SHIVAM WORK AREA
// Data access layer for Scan and ThreatLog entities
// Abstracts Prisma queries to keep services database-agnostic
// Follows CONTEXT.md: Polymorphic scan tracking with caching flags

import { prisma } from '../../config/database';
import { Scan, ScanType, RiskLevel, ThreatLog } from '@prisma/client';

export interface CreateScanData {
  userId: string;
  type: ScanType;
  targetData: string;
  riskScore?: number;
  riskLevel?: RiskLevel;
  category?: string;
  explanation?: string;
}

export interface CreateThreatLogData {
  scanId: string;
  heuristics: string[];
  mlFeatures?: Record<string, unknown>;
}

export class ScanRepository {
  async createScan(CreateScanData): Promise<Scan> {
    return prisma.scan.create({ data });
  }

  async getScanById(id: string): Promise<Scan | null> {
    return prisma.scan.findUnique({ where: { id } });
  }

  async getUserScans(userId: string, limit: number = 20, offset: number = 0): Promise<Scan[]> {
    return prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });
  }

  async getScansByUserIdAndType(userId: string, type: ScanType): Promise<Scan[]> {
    return prisma.scan.findMany({
      where: { userId, type },
      orderBy: { createdAt: 'desc' },
    });
  }

  async getRecentScans(limit: number = 100): Promise<Scan[]> {
    return prisma.scan.findMany({
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: { user: { select: { email: true } } }
    });
  }

  async createThreatLog(data: CreateThreatLogData): Promise<ThreatLog> {
    return prisma.threatLog.create({ data });
  }

  async findRecentCachedUrl(urlHash: string): Promise<Scan | null> {
    // Cache validity: 24 hours for URL scans to reduce AI engine load
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return prisma.scan.findFirst({
      where: {
        type: 'URL',
        targetData: urlHash,
        isCached: true,
        processedAt: { gte: twentyFourHoursAgo },
      },
      orderBy: { processedAt: 'desc' },
    });
  }

  async getScanStatistics(userId?: string) {
    const whereClause = userId ? { userId } : {};

    const [totalScans, riskLevels, recentScans] = await Promise.all([
      prisma.scan.count({ where: whereClause }),
      prisma.scan.groupBy({
        by: ['riskLevel'],
        where: whereClause,
        _count: true,
      }),
      prisma.scan.findMany({
        where: whereClause,
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: { id: true, type: true, riskLevel: true, createdAt: true }
      })
    ]);

    return {
      totalScans,
      riskDistribution: riskLevels.reduce((acc, curr) => ({
        ...acc,
        [curr.riskLevel || 'UNKNOWN']: curr._count
      }), {}),
      recentScans
    };
  }
}

export const scanRepository = new ScanRepository();