import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { uploadSingleFile } from '../middleware/upload.js';
import { loadFile, fileIdParamRules } from '../middleware/fileAccess.js';
import { validate } from '../middleware/validate.js';
import asyncHandler from '../utils/asyncHandler.js';
import * as filesController from '../controllers/files.controller.js';

const router = Router();

router.use(authenticate); // every file route requires a logged-in user

router.post('/', uploadSingleFile, asyncHandler(filesController.uploadFile));
router.get('/', asyncHandler(filesController.listFiles));
router.get('/:id', fileIdParamRules, validate, loadFile, asyncHandler(filesController.getFile));
router.get('/:id/download', fileIdParamRules, validate, loadFile, asyncHandler(filesController.downloadFile));
router.delete('/:id', fileIdParamRules, validate, loadFile, asyncHandler(filesController.deleteFile));

export default router;
