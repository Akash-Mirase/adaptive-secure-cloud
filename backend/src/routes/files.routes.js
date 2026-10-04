import { Router } from 'express';
import { body } from 'express-validator';
import { authenticate } from '../middleware/auth.js';
import { uploadSingleFile } from '../middleware/upload.js';
import { loadFile, fileIdParamRules } from '../middleware/fileAccess.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';
import * as filesController from '../controllers/files.controller.js';

const router = Router();

router.use(authenticate);
router.get('/:id/risk', fileIdParamRules, validate, loadFile, asyncHandler(filesController.getRiskBreakdown));

// SECURITY: the backend REFUSES any upload that is not declared as
// AES-256-GCM ciphertext. This is defense in depth — even if the frontend
// were bypassed or a bug shipped, the server-side gate still enforces the
// project's core requirement that nothing but ciphertext is ever stored.
const uploadRules = [
  body('iv')
    .isString().withMessage('iv must be text').bail()
    .isBase64().withMessage('iv must be base64').bail()
    .custom((value) => Buffer.from(value, 'base64').length === 12)
    .withMessage('iv must decode to exactly 12 bytes (96-bit AES-GCM IV)'),
  body('keyMetadata')
    .isString().withMessage('keyMetadata must be a JSON string').bail()
    .custom((value) => {
      let parsed;
      try { parsed = JSON.parse(value); } catch { throw new Error('keyMetadata must be valid JSON'); }
      if (parsed.algorithm !== 'AES-256-GCM') throw new Error('keyMetadata.algorithm must be AES-256-GCM');
      if (parsed.tagLength !== 128) throw new Error('keyMetadata.tagLength must be 128');
      return true;
    }),
  body('mimeType')
    .isString().withMessage('mimeType must be text').bail()
    .trim().isLength({ min: 1, max: 127 }).withMessage('mimeType is required'),
  body('originalSize')
    .isInt({ min: 0 }).withMessage('originalSize must be a non-negative integer').bail()
    .toInt(),
      body('userSensitivity')
    .optional()
    .isInt({ min: 0, max: 3 }).withMessage('userSensitivity must be an integer from 0 to 3').toInt(),
];

router.post('/', uploadSingleFile, uploadRules, validate, asyncHandler(filesController.uploadFile));
router.get('/', asyncHandler(filesController.listFiles));
router.get('/:id', fileIdParamRules, validate, loadFile, asyncHandler(filesController.getFile));
router.get('/:id/download', fileIdParamRules, validate, loadFile, asyncHandler(filesController.downloadFile));
router.get('/:id/key', fileIdParamRules, validate, loadFile, asyncHandler(filesController.getFileKey));
router.delete('/:id', fileIdParamRules, validate, loadFile, asyncHandler(filesController.deleteFile));

export default router;