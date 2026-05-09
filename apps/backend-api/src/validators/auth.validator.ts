import { z } from 'zod';

/**
 * Schema for POST /api/v1/auth/register
 * 
 * Rules:
 * - email: must be a properly formatted email address
 * - password: minimum 8 chars, must include uppercase, lowercase, and a digit
 * - name: optional string, trimmed of whitespace
 */
export const registerSchema = z.object({
  email: z
    .string({ required_error: 'Email is required' })
    .email('Invalid email address')
    .toLowerCase(), // normalize email to lowercase before hitting the service

  password: z
    .string({ required_error: 'Password is required' })
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),

  name: z
    .string()
    .trim()
    .min(1, 'Name cannot be empty')
    .optional(),
});

/**
 * Schema for POST /api/v1/auth/login
 * 
 * Rules:
 * - email: must be a properly formatted email address
 * - password: required, no complexity rules (to avoid user enumeration hints)
 */
export const loginSchema = z.object({
  email: z
    .string({ required_error: 'Email is required' })
    .email('Invalid email address')
    .toLowerCase(),

  password: z
    .string({ required_error: 'Password is required' })
    .min(1, 'Password is required'),
});

// Infer TypeScript types directly from Zod schemas.
// These can replace the manual DTOs in auth.types.ts if desired.
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
