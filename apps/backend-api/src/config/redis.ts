import Redis from 'ioredis';
import { env } from './env';

// Singleton Redis client instance.
// Shared across the entire backend — rate limiter, cache, queues all use this.
let redisClient: Redis | null = null;

/**
 * Returns the singleton Redis client, creating it on first call.
 * Uses lazy initialization so the connection is only established when needed.
 */
export const getRedisClient = (): Redis => {
  if (!redisClient) {
    redisClient = new Redis(env.REDIS_URL, {
      // Gracefully handle connection failures without crashing the process
      lazyConnect: true,
      // Retry strategy: attempt reconnect with exponential backoff, cap at 30s
      retryStrategy: (times: number) => {
        if (times > 10) {
          console.error('[Redis] Max reconnection attempts reached. Giving up.');
          return null; // Stop retrying
        }
        const delay = Math.min(times * 200, 30000);
        return delay;
      },
    });

    redisClient.on('connect', () => {
      console.log('[Redis] Connected successfully');
    });

    redisClient.on('error', (err: Error) => {
      console.error('[Redis] Connection error:', err.message);
    });

    redisClient.on('reconnecting', () => {
      console.warn('[Redis] Reconnecting...');
    });
  }

  return redisClient;
};

// Export the default instance for simple imports
export const redis = getRedisClient();
export default redis;

/**
 * Gracefully closes the Redis connection.
 */
export const closeRedisConnection = async (): Promise<void> => {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
    console.log('[Redis] Connection closed gracefully');
  }
};
