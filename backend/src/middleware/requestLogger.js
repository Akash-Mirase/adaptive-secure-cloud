import { env } from '../config/env.js';

// Logs method, path, status and duration only.
// SECURITY: never log headers, bodies or query strings. They can contain JWTs,
// passwords, and other secrets, and logs are often less protected than the database.
export function requestLogger(req, res, next) {
  if (env.nodeEnv === 'test') return next();

  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    const path = req.originalUrl.split('?')[0];
    console.log(`[http] ${req.method} ${path} ${res.statusCode} ${ms.toFixed(1)}ms`);
  });
  next();
}