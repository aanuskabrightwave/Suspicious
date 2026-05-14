import { Router } from 'express';
import { scanUrl, scanQrImage } from '../controllers/scanController';

const router = Router();

// Route handlers are protected by middleware applied in server.ts
router.post('/scan/url', scanUrl);
router.post('/scan/qr', scanQrImage); // Can also handle generic images for OCR

export default router;