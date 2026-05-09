import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';

// Standard 429 response handler — matches our global response format
const rateLimitHandler = (_req: Request, res: Response) => {
  res.status(429).json({
    success: false,
    message: 'Too many requests, please try again later',
  });
};

/**
 * Safe IP extractor — avoids ERR_ERL_KEY_GEN_IPV6 error.
 * Reads X-Forwarded-For for proxy/nginx environments, falls back to socket address.
 */
const getClientIp = (req: Request): string => {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ip = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    return ip.trim();
  }
  return req.socket?.remoteAddress ?? 'unknown';
};

/**
 * Strict rate limiter for authentication endpoints.
 * Limits: 10 attempts per 15 minutes per IP.
 * Protects: /auth/login, /auth/register
 * Purpose: Prevents brute-force attacks and credential stuffing.
 *
 * Uses in-memory store for local development.
 * In production with Redis, replace with RedisStore from rate-limit-redis.
 */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
  keyGenerator: getClientIp,
});

/**
 * General API rate limiter for public routes.
 * Limits: 100 requests per 15 minutes per IP.
 */
export const generalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
  keyGenerator: getClientIp,
});
