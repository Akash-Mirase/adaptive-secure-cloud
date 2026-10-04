import AppError from '../utils/AppError.js';
import { sendSuccess } from '../utils/apiResponse.js';
import * as userKeys from '../models/userKey.model.js';

// Authenticated lookup only (see routes). Returns JUST what's needed to
// share a file with someone: their id and PUBLIC key. Never anything wrapped.
export async function lookupUser(req, res) {
  const result = await userKeys.findPublicKeyByEmail(req.query.email);
  if (!result) throw new AppError('No registered user with that email', 404);
  return sendSuccess(res, { user: result });
}