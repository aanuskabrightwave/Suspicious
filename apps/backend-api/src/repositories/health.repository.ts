import { prisma } from '../config/database';

export class HealthRepository {
  // Repository's sole responsibility is direct Database Interaction.
  // It does not know about HTTP requests, validation, or business rules.
  public checkDatabaseConnection = async (): Promise<string> => {
    try {
      // Execute a simple query to verify database connection via Prisma
      await prisma.$queryRaw`SELECT 1`;
      return 'connected';
    } catch (error) {
      return 'disconnected';
    }
  };
}
