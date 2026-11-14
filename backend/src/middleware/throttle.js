import asyncHandler from '../utils/asyncHandler.js';
import AppError from '../utils/AppError.js';
import { hasRestriction } from '../services/anomaly.service.js';

export const blockIfThrottled = asyncHandler(async (req, res, next) => {
  if (await hasRestriction(req.user.id, 'THROTTLE_DOWNLOADS')) {
    throw new AppError('Downloads are temporarily limited due to unusual activity. Try again later.', 429);
  }
  next();
});