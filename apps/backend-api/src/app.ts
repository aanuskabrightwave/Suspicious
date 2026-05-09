import express from 'express';
import cors from 'cors';
import { env } from './config/env';
import apiRoutes from './routes/index';
import { notFoundHandler } from './middleware/notFound.middleware';
import { globalErrorHandler } from './middleware/error.middleware';

const app = express();

// ─────────────────────────────────────────────
// GLOBAL MIDDLEWARE — must run before all routes
// ─────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// API ROUTES — versioned via /api prefix
// ─────────────────────────────────────────────
app.use('/api', apiRoutes);

// ─────────────────────────────────────────────
// NOT FOUND — catches all unmatched routes
// ─────────────────────────────────────────────
app.use(notFoundHandler);

// ─────────────────────────────────────────────
// GLOBAL ERROR HANDLER — MUST be registered last
// Express identifies it as error middleware via the 4-argument signature
// ─────────────────────────────────────────────
app.use(globalErrorHandler);

app.listen(env.PORT, () => {
  console.log(`Server running on port ${env.PORT}`);
});

export default app;