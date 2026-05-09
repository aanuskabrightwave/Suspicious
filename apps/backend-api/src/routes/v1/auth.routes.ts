import { Router } from 'express';
import { AuthController } from '../../controllers/auth.controller';
import { authenticate } from '../../middleware/auth.middleware';
import { validate } from '../../middleware/validationMiddleware';
import { registerSchema, loginSchema } from '../../validators/auth.validator';
import { authRateLimiter } from '../../middleware/rateLimiter.middleware';

const router = Router();
const authController = new AuthController();

// ─────────────────────────────────────────────
// PUBLIC ROUTES — No authentication required
// ─────────────────────────────────────────────

// POST /api/v1/auth/register
// Flow: authRateLimiter → validate(registerSchema) → authController.register
router.post('/register', authRateLimiter, validate(registerSchema), authController.register);

// POST /api/v1/auth/login
// Flow: authRateLimiter → validate(loginSchema) → authController.login
router.post('/login', authRateLimiter, validate(loginSchema), authController.login);

// ─────────────────────────────────────────────
// PROTECTED ROUTES — JWT authentication required
// ─────────────────────────────────────────────

// GET /api/v1/auth/profile
// Flow: Request → authenticate middleware → authController.getProfile
router.get('/profile', authenticate, authController.getProfile);

// POST /api/v1/auth/logout
// Protected so the server can identify who is logging out
// Future: Invalidate refresh token associated with req.user.id
router.post('/logout', authenticate, authController.logout);

export default router;
