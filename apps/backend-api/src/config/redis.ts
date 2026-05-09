// SHIVAM WORK AREA
/**
 * apps/backend-api/src/config/redis.ts
 */
import Redis from 'ioredis';
import { logger } from '../utils/logger';

const redisConfig = {
  host: process.env.REDIS_HOST || 'localhost',
  port: Number(process.env.REDIS_PORT) || 6379,
  maxRetriesPerRequest: null,
};

export const redis = new Redis(redisConfig);

redis.on('connect', () => logger.info('Redis connected'));
redis.on('error', (err) => logger.error('Redis connection error', { err }));

export default redis;