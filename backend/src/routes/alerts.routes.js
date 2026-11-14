import { Router } from 'express';
import { query as q } from 'express-validator';
import { authenticate, requireRole } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';
import * as c from '../controllers/alerts.controller.js';

const router = Router();
router.use(authenticate);
const paging = [q('page').optional().isInt({ min: 1 }).toInt(), q('pageSize').optional().isInt({ min: 1, max: 100 }).toInt()];
router.get('/me', paging, validate, asyncHandler(c.mine));
router.get('/', requireRole('ADMIN'), paging, validate, asyncHandler(c.all));
export default router;