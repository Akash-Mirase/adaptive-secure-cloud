import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

// Stricter than the global limiter. Tests use a high default so they are not throttled.
export function createAuthLimiter({ limit = env.nodeEnv === 'test' ? 1000 : 10, skipSuccessfulRequests = false } = {}) {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    limit,
    skipSuccessfulRequests, // when true, only failed responses (status 400 and above) are counted
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many attempts. Please try again later.', data: null },
  });
}

// Login: only FAILED attempts count, so normal users are never throttled.
export const loginLimiter = createAuthLimiter({ skipSuccessfulRequests: true });
// Register: every attempt counts, which slows down mass account creation.
export const registerLimiter = createAuthLimiter();
// Recovery is powerful (it resets the password), so it gets the tightest limit.
export const recoveryLimiter = createAuthLimiter({ limit: env.nodeEnv === 'test' ? 1000 : 5, skipSuccessfulRequests: false });