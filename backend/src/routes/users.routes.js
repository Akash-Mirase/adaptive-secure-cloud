import { Router } from 'express';
import { query as queryParam } from 'express-validator';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';
import { lookupUser } from '../controllers/users.controller.js';

const router = Router();

// SECURITY: requires authentication. This still reveals whether an email is
// registered to any logged-in user, which is an inherent, documented
// trade-off of a usable "share with this email" feature (see Phase 12
// honest limitations). It does NOT work for anonymous/unauthenticated callers.
router.get(
  '/lookup',
  authenticate,
  [queryParam('email').isString().withMessage('email must be text').bail().trim().toLowerCase().isEmail().withMessage('email is not valid')],
  validate,
  asyncHandler(lookupUser)
);

export default router;