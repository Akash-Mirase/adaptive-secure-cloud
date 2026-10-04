import { Router } from 'express';
import { body, param } from 'express-validator';
import { authenticate } from '../middleware/auth.js';
import { uploadSingleFile } from '../middleware/upload.js';
import { loadFileOwned, loadFileForAccess, requireAccessLevel, fileIdParamRules } from '../middleware/fileAccess.js';
import { enforceRiskPolicy } from '../middleware/riskPolicy.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';
import * as filesController from '../controllers/files.controller.js';

const router = Router();
router.use(authenticate);

const base64 = (field, label) =>
  body(field).isString().withMessage(`${label} must be text`).bail().isBase64().withMessage(`${label} must be base64`);

const uploadRules = [
  body('iv').isString().bail().isBase64().bail().custom((v) => Buffer.from(v, 'base64').length === 12).withMessage('iv must decode to exactly 12 bytes'),
  body('keyMetadata').isString().bail().custom((value) => {
    let parsed;
    try { parsed = JSON.parse(value); } catch { throw new Error('keyMetadata must be valid JSON'); }
    if (parsed.algorithm !== 'AES-256-GCM') throw new Error('keyMetadata.algorithm must be AES-256-GCM');
    if (parsed.tagLength !== 128) throw new Error('keyMetadata.tagLength must be 128');
    return true;
  }),
  body('mimeType').isString().bail().trim().isLength({ min: 1, max: 127 }),
  body('originalSize').isInt({ min: 0 }).bail().toInt(),
  base64('wrappedFek', 'wrappedFek'),
  body('wrapIv').isString().bail().isBase64().bail().custom((v) => Buffer.from(v, 'base64').length === 12).withMessage('wrapIv must decode to exactly 12 bytes'),
  body('userSensitivity').optional().isInt({ min: 0, max: 3 }).toInt(),
];

const shareRules = [
  body('email').isString().bail().trim().toLowerCase().isEmail().withMessage('email is not valid'),
  body('permission').isIn(['VIEW', 'DOWNLOAD', 'EDIT']).withMessage('permission must be VIEW, DOWNLOAD, or EDIT'),
  base64('wrappedFek', 'wrappedFek'),
];
const revokeParamRules = [...fileIdParamRules, param('userId').isInt({ min: 1 }).toInt()];

// Order matters: list route BEFORE the ':id' routes so it isn't swallowed by them.
router.get('/shared-with-me', asyncHandler(filesController.listSharedWithMe));

router.post('/', uploadSingleFile, uploadRules, validate, asyncHandler(filesController.uploadFile));
router.get('/', asyncHandler(filesController.listFiles));

router.get('/:id', fileIdParamRules, validate, loadFileForAccess, asyncHandler(filesController.getFile));
router.get('/:id/risk', fileIdParamRules, validate, loadFileForAccess, asyncHandler(filesController.getRiskBreakdown));
router.get('/:id/download', fileIdParamRules, validate, loadFileForAccess, requireAccessLevel('DOWNLOAD'), enforceRiskPolicy, asyncHandler(filesController.downloadFile));
router.get('/:id/key', fileIdParamRules, validate, loadFileForAccess, requireAccessLevel('DOWNLOAD'), enforceRiskPolicy, asyncHandler(filesController.getFileKey));

router.delete('/:id', fileIdParamRules, validate, loadFileOwned, asyncHandler(filesController.deleteFile));

router.get('/:id/permissions', fileIdParamRules, validate, loadFileOwned, asyncHandler(filesController.listPermissionsForFile));
router.post('/:id/share', fileIdParamRules, validate, loadFileOwned, shareRules, validate, asyncHandler(filesController.shareFile));
router.delete('/:id/share/:userId', revokeParamRules, validate, loadFileOwned, asyncHandler(filesController.revokeShare));

export default router;