// SHIVAM WORK AREA
/**
 * apps/backend-api/src/middleware/validation.ts
 */
import { Request, Response, NextFunction } from 'express';
import { validationResult, body } from 'express-validator';

export const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

export const scanUrlValidation = [
  body('url').isURL().withMessage('Invalid URL provided'),
  validateRequest,
];
