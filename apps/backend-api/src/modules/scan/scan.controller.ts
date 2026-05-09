// SHIVAM WORK AREA
/**
 * apps/backend-api/src/modules/scan/scan.controller.ts
 */
import { Request, Response } from 'express';
import { ScanService } from './scan.service';

const scanService = new ScanService();

export class ScanController {
  async scanUrl(req: any, res: Response) {
    const { url } = req.body;
    const userId = req.user.id;

    const result = await scanService.initiateUrlScan(url, userId);
    
    if (result.isProcessed) {
      return res.json(result);
    }

    res.status(202).json({
      message: 'Scan initiated',
      scanId: result.id,
    });
  }

  async getHistory(req: any, res: Response) {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 20;
    const userId = req.user.id;

    const scans = await scanService.getUserScans(userId, page, limit);
    res.json({ items: scans, page, limit });
  }
}
