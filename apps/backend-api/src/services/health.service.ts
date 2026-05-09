import { HealthRepository } from '../repositories/health.repository';

export class HealthService {
  private healthRepository: HealthRepository;

  constructor() {
    this.healthRepository = new HealthRepository();
  }

  // Service's sole responsibility is Business Logic.
  // It fetches data from the Repository, processes it, and returns the result.
  public getSystemHealth = async () => {
    // Delegate database interactions to the Repository layer
    const dbStatus = await this.healthRepository.checkDatabaseConnection();
    
    return {
      server: 'running',
      database: dbStatus,
      timestamp: new Date().toISOString(),
    };
  };
}
