import { Router } from 'express';
import { body } from 'express-validator';
import * as authController from '../controllers/auth.controller.js';
import { authenticate } from '../middleware/auth.js';
import { loginLimiter, registerLimiter } from '../middleware/rateLimiters.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';

const router = Router();

const registerRules = [
  body('name')
    .isString().withMessage('name must be text').bail()
    .trim()
    .isLength({ min: 2, max: 100 }).withMessage('name must be 2 to 100 characters'),
  body('email')
    .isString().withMessage('email must be text').bail()
    .trim()
    .toLowerCase()
    .isEmail().withMessage('email is not valid').bail()
    .isLength({ max: 254 }).withMessage('email is too long'),
  // The password is NEVER trimmed or altered. Length rules follow NIST guidance:
  // long is better than "complex". The 72-BYTE cap exists because bcrypt silently
  // ignores everything after 72 bytes, so we refuse to pretend those bytes count.
  body('password')
    .isString().withMessage('password must be text').bail()
    .isLength({ min: 12 }).withMessage('password must be at least 12 characters').bail()
    .custom((value) => Buffer.byteLength(value, 'utf8') <= 72)
    .withMessage('password must be at most 72 bytes (bcrypt limit)'),
];

// Login rules only check shape (no strength rules), so errors reveal nothing.
const loginRules = [
  body('email')
    .isString().withMessage('email must be text').bail()
    .trim()
    .toLowerCase()
    .isEmail().withMessage('email is not valid'),
  body('password')
    .isString().withMessage('password must be text').bail()
    .isLength({ min: 1, max: 256 }).withMessage('password is required'),
];

router.post('/register', registerLimiter, registerRules, validate, asyncHandler(authController.register));
router.post('/login', loginLimiter, loginRules, validate, asyncHandler(authController.login));
router.get('/me', authenticate, asyncHandler(authController.me));
router.post('/logout', authenticate, asyncHandler(authController.logout));

export default router;