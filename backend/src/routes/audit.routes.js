import { Router } from 'express';
import { query as queryParam } from 'express-validator';
import { authenticate, requireRole } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';
import * as auditController from '../controllers/audit.controller.js';

const router = Router();
router.use(authenticate);

// Mirrors audit_logs.event_type exactly (Phase 4 schema). Kept here, not
// imported from the DB, so validation fails fast with a clear 400 instead of
// a confusing DB-level error if a filter value is typo'd.
const EVENT_TYPES = [
  'REGISTER', 'LOGIN', 'LOGIN_FAILED', 'LOGOUT', 'UPLOAD', 'DOWNLOAD', 'DELETE',
  'SHARE', 'UNSHARE', 'ACCESS_DENIED', 'KEY_OPERATION', 'RISK_CLASSIFICATION',
  'SECURITY_POLICY_APPLIED', 'STEP_UP_VERIFICATION', 'INTEGRITY_FAILURE',
];

const filterRules = [
  queryParam('eventType').optional().isIn(EVENT_TYPES).withMessage('invalid eventType'),
  queryParam('result').optional().isIn(['SUCCESS', 'FAILURE', 'DENIED']).withMessage('invalid result'),
  queryParam('fileId').optional().isUUID().withMessage('invalid fileId'),
  queryParam('dateFrom').optional().isISO8601().withMessage('dateFrom must be an ISO date'),
  queryParam('dateTo').optional().isISO8601().withMessage('dateTo must be an ISO date'),
  queryParam('page').optional().isInt({ min: 1 }).toInt(),
  queryParam('pageSize').optional().isInt({ min: 1, max: 100 }).toInt(),
];
const adminFilterRules = [...filterRules, queryParam('userId').optional().isInt({ min: 1 }).toInt()];

router.get('/me', filterRules, validate, asyncHandler(auditController.listMine));
router.get('/me/stats', asyncHandler(auditController.myStats));

router.get('/', requireRole('ADMIN'), adminFilterRules, validate, asyncHandler(auditController.listAll));
router.get('/stats', requireRole('ADMIN'), adminFilterRules, validate, asyncHandler(auditController.allStats));

export default router;