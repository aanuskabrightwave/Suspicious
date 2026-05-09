import { Router } from 'express';
import healthRoutes from './health.routes';
import authRoutes from './auth.routes';

const router = Router();

// Minimal route registration for v1
// Maps specific feature domains to their dedicated route files
router.use('/health', healthRoutes);
router.use('/auth', authRoutes);

export default router;
