// SHIVAM WORK AREA
/**
 * apps/backend-api/src/modules/scan/scan.routes.ts
 */
import { Router } from 'express';
import { ScanController } from './scan.controller';
import { authenticateJWT } from '../../middleware/auth';
import { scanUrlValidation } from '../../middleware/validation';
import { asyncHandler } from '../../utils/asyncHandler';

const router = Router();
const controller = new ScanController();

router.use(authenticateJWT);

router.post('/url', scanUrlValidation, asyncHandler(controller.scanUrl));
router.get('/', asyncHandler(controller.getHistory));

export default router;
