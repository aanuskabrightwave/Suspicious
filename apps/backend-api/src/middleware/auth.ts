// SHIVAM WORK AREA
/**
 * apps/backend-api/src/middleware/auth.ts
 */
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../config/database';

export const authenticateJWT = async (req: any, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET!, async (err: any, user: any) => {
      if (err) return res.sendStatus(403);

      const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
      if (!dbUser) return res.sendStatus(403);

      req.user = dbUser;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

export const requireRole = (roles: string[]) => (req: any, res: Response, next: NextFunction) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Insufficient permissions' });
  }
  next();
};
