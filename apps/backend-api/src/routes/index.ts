import { Router } from 'express';
import v1Routes from './v1';

const router = Router();

// API Versioning Setup
// All v1 routes will be prefixed with /api/v1 (set in app.ts later)
router.use('/v1', v1Routes);

export default router;
