import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/AppError';
import { env } from '../config/env';

// Global error handling middleware
export const globalErrorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Default to 500 internal server error if not specified
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal server error';

  if (env.NODE_ENV === 'development') {
    // In development, send the full stack trace for easier debugging
    res.status(statusCode).json({
      success: false,
      message: message,
      error: err,
      stack: err.stack,
    });
  } else {
    // In production, carefully sanitize errors
    if (err instanceof AppError && err.isOperational) {
      // Known operational errors (e.g. validation, not found) can be sent to client
      res.status(statusCode).json({
        success: false,
        message: message,
      });
    } else {
      // Programming or unknown errors: Don't leak details to the client
      console.error('ERROR 💥:', err); // Send to logging system
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
};
