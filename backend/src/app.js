import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import { env } from './config/env.js';
import healthRoutes from './routes/health.routes.js';
import { notFound, errorHandler } from './middleware/errorHandler.js';

const app = express();

// Don't advertise the framework to attackers.
app.disable('x-powered-by');

// Secure HTTP headers (CSP, HSTS, X-Content-Type-Options, etc.)
app.use(helmet());

// Only our frontend origin may call this API from a browser.
app.use(cors({ origin: env.corsOrigins, credentials: true }));

// Small JSON limit: file bytes will use multer, never the JSON parser.
app.use(express.json({ limit: '1mb' }));

// Global rate limit (stricter limits for login/register come in Phase 5).
app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many requests, slow down.', data: null },
  })
);

app.use('/api/health', healthRoutes);

app.use(notFound);
app.use(errorHandler);

export default app;