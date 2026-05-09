// SHIVAM WORK AREA
/**
 * apps/backend-api/src/index.ts
 */
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { createServer } from 'http';
import rateLimit from 'express-rate-limit';
import { initializeSocket } from './config/socket';
import { errorHandler } from './middleware/errorHandler';
import scanRoutes from './modules/scan/scan.routes';
import { logger } from './utils/logger';

const app = express();
const httpServer = createServer(app);

// Security
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes',
});
app.use(limiter);

// Initialization
initializeSocket(httpServer);

// Routes
app.use('/api/v1/scans', scanRoutes);

// TODO: Add threat intelligence sharing with other instances

// Error Handling
app.use(errorHandler);

const PORT = process.env.BACKEND_PORT || 3000;
httpServer.listen(PORT, () => {
  logger.info(`Backend API listening on port ${PORT}`);
});
