import { Request, Response } from 'express';
import { HealthService } from '../services/health.service';

export class HealthController {
  private healthService: HealthService;

  constructor() {
    this.healthService = new HealthService();
  }

  // Controller's sole responsibility is handling Request and Response.
  // It extracts data from req, passes it to the Service, and formats the res.
  public checkHealth = async (req: Request, res: Response): Promise<void> => {
    try {
      // Delegate to Service layer
      const status = await this.healthService.getSystemHealth();
      
      res.status(200).json({
        success: true,
        data: status,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Health check failed',
      });
    }
  };
}
