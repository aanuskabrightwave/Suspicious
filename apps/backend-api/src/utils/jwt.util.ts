import jwt from 'jsonwebtoken';
import { env } from '../config/env';

// 1. Token Payload Typing
// We strictly define the structure of the data embedded inside the JWT.
// This prevents random, undocumented data from being injected into tokens
// and ensures type safety when decoding tokens in our middleware.
export interface JwtPayload {
  userId: string;
  // Additional claims (like roles or permissions) can be added here as the app scales
}

export class JwtUtil {
  /**
   * Generates a short-lived Access Token for authenticating stateless API requests.
   * 
   * @param payload - The strictly typed user data (e.g., userId) to encode
   * @returns The signed JWT string
   */
  public static generateAccessToken(payload: JwtPayload): string {
    // The secret is safely pulled from the centralized, validated env config
    return jwt.sign(payload, env.JWT_SECRET, {
      expiresIn: '15m', // Short lifespan limits the damage window if a token is stolen
    });
  }

  /**
   * Verifies an incoming Token to ensure it is valid, not expired, and signed by our server.
   * 
   * @param token - The JWT string extracted from the Authorization header
   * @returns The decoded, strongly-typed payload
   */
  public static verifyAccessToken(token: string): JwtPayload {
    // jwt.verify automatically throws an error if the token is expired or tampered with.
    // The auth middleware will catch this error and return a 401 Unauthorized.
    return jwt.verify(token, env.JWT_SECRET) as JwtPayload;
  }

  /**
   * SCALABILITY: Generates a long-lived Refresh Token for obtaining new Access Tokens.
   * This is prepared for future implementation when frontend needs persistent login sessions.
   * 
   * @param payload - The strictly typed user data
   * @returns The signed JWT string
   */
  public static generateRefreshToken(payload: JwtPayload): string {
    return jwt.sign(payload, env.JWT_SECRET, {
      expiresIn: '7d', // Refresh tokens live much longer but should eventually be rotated
    });
  }
}
