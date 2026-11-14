import { Router } from 'express';
import { body } from 'express-validator';
import { authenticate } from '../middleware/auth.js';
import { mfaLimiter } from '../middleware/rateLimiters.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';
import * as c from '../controllers/mfa.controller.js';

const router = Router();
router.use(authenticate);

const pw = body('password').isString().withMessage('password is required').bail().isLength({ min: 1, max: 256 });
const totp = (optional = false) => {
  const r = body('code'); return (optional ? r.optional() : r).matches(/^\d{6}$/).withMessage('code must be 6 digits');
};
const recovery = body('recoveryCode').optional().isString().isLength({ min: 10, max: 40 });

router.get('/status', asyncHandler(c.status));
router.post('/enroll', mfaLimiter, [pw], validate, asyncHandler(c.enroll));
router.post('/enroll/confirm', mfaLimiter, [totp()], validate, asyncHandler(c.confirm));
router.post('/disable', mfaLimiter, [pw, totp(true), recovery], validate, asyncHandler(c.disable));
router.post('/recovery-codes', mfaLimiter, [pw, totp()], validate, asyncHandler(c.regenerate));

export default router;