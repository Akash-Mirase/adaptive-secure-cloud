import { param } from 'express-validator';
import asyncHandler from '../utils/asyncHandler.js';
import AppError from '../utils/AppError.js';
import * as fileModel from '../models/file.model.js';
import * as permissionModel from '../models/permission.model.js';
import { permissionAtLeast } from '../config/permissions.js';
import { logEvent } from '../services/audit.service.js';

export const fileIdParamRules = [param('id').isUUID().withMessage('invalid file id')];

// STRICT ownership only. Use for actions only the true owner may do:
// delete, manage sharing (grant/revoke), list who has access.
export const loadFileOwned = asyncHandler(async (req, res, next) => {
  const file = await fileModel.findById(req.params.id);
  if (!file || file.status !== 'ACTIVE' || file.ownerId !== req.user.id) {
    if (file) {
      await logEvent({ userId: req.user.id, eventType: 'ACCESS_DENIED', fileId: file.id, result: 'DENIED', ipAddress: req.ip, details: { reason: 'NOT_OWNER' } });
    }
    throw new AppError('File not found', 404); // 404, not 403 — see Phase 6 rationale
  }
  req.targetFile = file;
  req.accessLevel = 'OWNER';
  next();
});

// Owner OR a user with a granted permission row. Use for read-type actions
// (view metadata, see risk info, download, fetch key) that a shared
// recipient may also be allowed to perform, at whatever level they were granted.
export const loadFileForAccess = asyncHandler(async (req, res, next) => {
  const file = await fileModel.findById(req.params.id);
  if (!file || file.status !== 'ACTIVE') throw new AppError('File not found', 404);

  if (file.ownerId === req.user.id) {
    req.targetFile = file;
    req.accessLevel = 'OWNER';
    return next();
  }

  const permission = await permissionModel.find(file.id, req.user.id);
  if (!permission) {
    await logEvent({ userId: req.user.id, eventType: 'ACCESS_DENIED', fileId: file.id, result: 'DENIED', ipAddress: req.ip, details: { reason: 'NO_PERMISSION' } });
    throw new AppError('File not found', 404); // still 404: don't confirm the file's existence to a non-permitted user
  }

  req.targetFile = file;
  req.accessLevel = permission.permission;
  next();
});

// Use AFTER loadFileForAccess. The requester has SOME access (so the file's
// existence is already legitimately known to them) — a 403 here is honest
// and not an information leak.
export function requireAccessLevel(minLevel) {
  return asyncHandler(async (req, res, next) => {
    if (!permissionAtLeast(req.accessLevel, minLevel)) {
      await logEvent({
        userId: req.user.id, eventType: 'ACCESS_DENIED', fileId: req.targetFile.id, result: 'DENIED', ipAddress: req.ip,
        details: { reason: 'INSUFFICIENT_PERMISSION', have: req.accessLevel, need: minLevel },
      });
      throw new AppError('You do not have sufficient permission for this action', 403);
    }
    next();
  });
}