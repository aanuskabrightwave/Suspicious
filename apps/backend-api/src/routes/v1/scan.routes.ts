import { Router } from 'express';
import { ScanController } from '../../controllers/scan.controller';
import { authenticate } from '../../middleware/auth.middleware';
import { validate } from '../../middleware/validationMiddleware';
import { scanUrlSchema } from '../../validators/scan.validator';

const router = Router();
const scanController = new ScanController();

/**
 * PROTECTED ROUTES
 * Scanning requires the user to be authenticated.
 */

// POST /api/v1/scan/url
// Analyzes a URL for potential security threats using heuristic detection.
router.post('/url', authenticate, validate(scanUrlSchema), scanController.scanUrl);

// GET /api/v1/scan/history
// Retrieves the authenticated user's scan history.
router.get('/history', authenticate, scanController.getHistory);

export default router;
