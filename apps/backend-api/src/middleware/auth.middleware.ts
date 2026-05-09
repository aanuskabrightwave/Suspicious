import { Response, NextFunction } from 'express';
import { JwtUtil } from '../utils/jwt.util';
import { AuthRepository } from '../repositories/auth.repository';
import { AppError } from '../utils/AppError';
import { AuthenticatedRequest } from '../controllers/auth.controller';

const authRepository = new AuthRepository();

/**
 * Protects routes by verifying the incoming JWT Bearer token.
 * If valid, it attaches the authenticated user to req.user and calls next().
 * If invalid or missing, it forwards an AppError to the Global Error Handler.
 * 
 * Usage: Apply to any route that requires authentication.
 * Example: router.get('/profile', authenticate, authController.getProfile)
 */
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // 1. Extract the Authorization header
    const authHeader = req.headers.authorization;

    // 2. Validate the header format — must be "Bearer <token>"
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(new AppError(401, 'Authentication required. No token provided.'));
    }

    // 3. Isolate the raw token string
    const token = authHeader.split(' ')[1];

    if (!token) {
      return next(new AppError(401, 'Authentication required. Token is malformed.'));
    }

    // 4. Verify and decode the JWT using the centralized utility
    // jwt.verify will automatically throw if the token is expired or tampered with
    const decoded = JwtUtil.verifyAccessToken(token);

    // 5. Cross-check: Fetch the user from the database to confirm they still exist
    // This handles the case where a user was deleted but their token hasn't expired yet
    const user = await authRepository.findUserById(decoded.userId);

    if (!user) {
      return next(new AppError(401, 'The user belonging to this token no longer exists.'));
    }

    // 6. Attach a sanitized, typed user object to the request
    // We only expose the minimum safe fields — never the password hash
    req.user = {
      id: user.id,
      email: user.email,
    };

    // 7. Pass control to the next middleware/controller
    next();
  } catch (error: any) {
    // Handle specific JWT errors with clear, secure messages
    if (error.name === 'TokenExpiredError') {
      return next(new AppError(401, 'Your session has expired. Please log in again.'));
    }

    if (error.name === 'JsonWebTokenError') {
      return next(new AppError(401, 'Invalid token. Please log in again.'));
    }

    // Forward any unexpected errors to the Global Error Handler
    return next(error);
  }
};
