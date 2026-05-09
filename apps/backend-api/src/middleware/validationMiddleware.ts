import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

/**
 * A reusable Higher-Order Function that accepts a Zod schema and returns
 * an Express middleware. If validation passes, request proceeds to the controller.
 * If it fails, a structured 400 response is immediately returned.
 * 
 * Usage in routes: router.post('/register', validate(registerSchema), authController.register)
 * 
 * @param schema - Any Zod schema to validate req.body against
 */
export const validate = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      // Format Zod's error structure into a clean flat key-value map
      // e.g. { "email": "Invalid email address", "password": "Too short" }
      const errors = formatZodErrors(result.error);

      res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors,
      });
      return;
    }

    // Overwrite req.body with the Zod-parsed and type-coerced result.
    // This ensures controllers always receive sanitized, validated data.
    req.body = result.data;
    next();
  };
};

/**
 * Converts Zod's nested error format into a flat, readable key-value object.
 * Makes error responses predictable and easy to consume on the frontend.
 */
const formatZodErrors = (error: ZodError): Record<string, string> => {
  return error.errors.reduce((acc, curr) => {
    // curr.path is an array like ['email'] or ['address', 'city']
    const key = curr.path.join('.');
    acc[key] = curr.message;
    return acc;
  }, {} as Record<string, string>);
};