import { Router } from 'express';
import { body, query as queryParam } from 'express-validator';
import * as authController from '../controllers/auth.controller.js';
import { authenticate } from '../middleware/auth.js';
import { loginLimiter, registerLimiter, recoveryLimiter } from '../middleware/rateLimiters.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';

const router = Router();

const base64 = (field, label) =>
  body(field).isString().withMessage(`${label} must be text`).bail().isBase64().withMessage(`${label} must be base64`);

const passwordRules = (field) =>
  body(field)
    .isString().withMessage(`${field} must be text`).bail()
    .isLength({ min: 12 }).withMessage(`${field} must be at least 12 characters`).bail()
    .custom((value) => Buffer.byteLength(value, 'utf8') <= 72).withMessage(`${field} must be at most 72 bytes (bcrypt limit)`);

const registerRules = [
  body('name').isString().withMessage('name must be text').bail().trim().isLength({ min: 2, max: 100 }).withMessage('name must be 2 to 100 characters'),
  body('email').isString().withMessage('email must be text').bail().trim().toLowerCase().isEmail().withMessage('email is not valid').bail().isLength({ max: 254 }).withMessage('email is too long'),
  passwordRules('password'),

  // Key hierarchy fields — all generated client-side, none are secrets except recoveryKey.
  base64('kdfSalt', 'kdfSalt'),
  body('kdfIterations').isInt({ min: 100000, max: 5000000 }).withMessage('kdfIterations must be between 100,000 and 5,000,000').toInt(),
  base64('wrappedMasterKey', 'wrappedMasterKey'),
  base64('masterKeyIv', 'masterKeyIv').custom((v) => Buffer.from(v, 'base64').length === 12).withMessage('masterKeyIv must decode to 12 bytes'),

  base64('recoveryWrappedMasterKey', 'recoveryWrappedMasterKey'),
  base64('recoveryIv', 'recoveryIv').custom((v) => Buffer.from(v, 'base64').length === 12).withMessage('recoveryIv must decode to 12 bytes'),
  body('recoveryKey').isString().withMessage('recoveryKey must be text').bail().isLength({ min: 16, max: 128 }).withMessage('recoveryKey looks invalid'),
];

const loginRules = [
  body('email').isString().withMessage('email must be text').bail().trim().toLowerCase().isEmail().withMessage('email is not valid'),
  body('password').isString().withMessage('password must be text').bail().isLength({ min: 1, max: 256 }).withMessage('password is required'),
];

const recoveryBundleRules = [queryParam('email').isString().bail().trim().toLowerCase().isEmail().withMessage('email is not valid')];

const recoverRules = [
  body('email').isString().bail().trim().toLowerCase().isEmail().withMessage('email is not valid'),
  body('recoveryKey').isString().withMessage('recoveryKey must be text').bail().isLength({ min: 16, max: 128 }),
  passwordRules('newPassword'),
  base64('kdfSalt', 'kdfSalt'),
  body('kdfIterations').isInt({ min: 100000, max: 5000000 }).toInt(),
  base64('wrappedMasterKey', 'wrappedMasterKey'),
  base64('masterKeyIv', 'masterKeyIv').custom((v) => Buffer.from(v, 'base64').length === 12).withMessage('masterKeyIv must decode to 12 bytes'),
];

router.post('/register', registerLimiter, registerRules, validate, asyncHandler(authController.register));
router.post('/login', loginLimiter, loginRules, validate, asyncHandler(authController.login));
router.get('/me', authenticate, asyncHandler(authController.me));
router.post('/logout', authenticate, asyncHandler(authController.logout));

router.get('/keys', authenticate, asyncHandler(authController.getKeys));
router.get('/recovery-bundle', recoveryLimiter, recoveryBundleRules, validate, asyncHandler(authController.getRecoveryBundle));
router.post('/recover', recoveryLimiter, recoverRules, validate, asyncHandler(authController.recover));

export default router;