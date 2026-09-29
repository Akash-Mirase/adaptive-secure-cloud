import { param } from 'express-validator';
import asyncHandler from '../utils/asyncHandler.js';
import AppError from '../utils/AppError.js';
import * as fileModel from '../models/file.model.js';
import { logEvent } from '../services/audit.service.js';

export const fileIdParamRules = [param('id').isUUID().withMessage('invalid file id')];

// Loads the file named in :id and checks ownership.
// Phase 12 extends this to also allow a user who was granted a permission.
export const loadFile = asyncHandler(async (req, res, next) => {
  const file = await fileModel.findById(req.params.id);

  if (!file || file.status !== 'ACTIVE') throw new AppError('File not found', 404);

  if (file.ownerId !== req.user.id) {
    await logEvent({
      userId: req.user.id,
      eventType: 'ACCESS_DENIED',
      fileId: file.id,
      result: 'DENIED',
      ipAddress: req.ip,
      details: { reason: 'NOT_OWNER' },
    });
    // SECURITY: 404, not 403. A 403 would confirm the file exists but isn't
    // theirs; 404 gives an attacker no information either way.
    throw new AppError('File not found', 404);
  }

  req.targetFile = file;
  next();
});