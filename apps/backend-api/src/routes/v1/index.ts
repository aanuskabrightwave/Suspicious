import { Router } from 'express';
import healthRoutes from './health.routes';
import authRoutes from './auth.routes';
import scanRoutes from './scan.routes';

const router = Router();

// Minimal route registration for v1
// Maps specific feature domains to their dedicated route files
router.use('/health', healthRoutes);
router.use('/auth', authRoutes);
router.use('/scan', scanRoutes);

export default router;
