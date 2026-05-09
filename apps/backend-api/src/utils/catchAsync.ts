import { Request, Response, NextFunction } from 'express';

// Type definition for Express route handler functions
type AsyncFunction = (req: Request, res: Response, next: NextFunction) => Promise<any>;

// Wrapper function to catch unhandled promise rejections in async routes
export const catchAsync = (fn: AsyncFunction) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Execute the async route and pass any errors to Express's next()
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
