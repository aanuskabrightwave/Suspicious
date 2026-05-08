import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// ======================================
// SHIVAM WORK AREA
// Validate JWT tokens
// Inject user object into request
// Handle token expiration logic
// ======================================

export const protect = (req: Request, res: Response, next: NextFunction) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ error: 'Not authorized, no token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    (req as any).user = decoded; // Attach user payload
    next();
  } catch (error) {
    res.status(401).json({ error: 'Not authorized, token failed' });
  }
};
