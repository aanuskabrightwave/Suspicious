import { Response } from 'express';
import { ScanService } from '../services/scan.service';
import { catchAsync } from '../utils/catchAsync';
import { ScanUrlDto } from '../types/scan.types';
import { AuthenticatedRequest } from './auth.controller';

export class ScanController {
  private scanService: ScanService;

  constructor() {
    this.scanService = new ScanService();
  }

  /**
   * POST /api/v1/scan/url
   * Processes a URL and saves the result to the user's history.
   */
  public scanUrl = catchAsync(async (req: AuthenticatedRequest, res: Response) => {
    const data: ScanUrlDto = req.body;
    const userId = req.user!.id; // Middleware guarantees req.user exists

    const result = await this.scanService.analyzeUrl(data, userId);

    res.status(200).json({
      success: true,
      message: 'URL scan completed and saved',
      data: result,
    });
  });

  /**
   * GET /api/v1/scan/history
   * Fetches the authenticated user's personal scan history.
   */
  public getHistory = catchAsync(async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.id;

    const history = await this.scanService.getHistory(userId);

    res.status(200).json({
      success: true,
      message: 'Scan history fetched successfully',
      data: history,
    });
  });
}
