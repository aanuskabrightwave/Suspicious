import { Router } from 'express';
import { HealthController } from '../../controllers/health.controller';

const router = Router();
const healthController = new HealthController();

// Route → Controller mapping
// Defines the exact HTTP methods and endpoints for the health domain
router.get('/', healthController.checkHealth);

export default router;
