import { Router } from 'express';
import asyncHandler from '../utils/asyncHandler.js';
import { getHealth, getDbHealth, getS3Health } from '../controllers/health.controller.js';

const router = Router();

router.get('/', getHealth);
router.get('/db', asyncHandler(getDbHealth));
router.get('/s3', asyncHandler(getS3Health));

export default router;