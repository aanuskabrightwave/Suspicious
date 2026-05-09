import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/AppError';

// Middleware for catching requests to unhandled routes
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
  // We simply pass an AppError to next().
  // The Express framework will automatically route this down to the globalErrorHandler.
  next(new AppError(404, `Not Found - ${req.originalUrl}`));
};
