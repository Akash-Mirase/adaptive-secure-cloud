import { Router } from 'express';
import { getHealth, getDbHealth } from '../controllers/health.controller.js';
import asyncHandler from '../utils/asyncHandler.js';

const router = Router();

router.get('/', getHealth);
router.get('/db', asyncHandler(getDbHealth));

export default router;