import { validationResult } from 'express-validator';
import { sendError } from '../utils/apiResponse.js';

// Put AFTER an array of express-validator rules on a route.
// SECURITY: never trust client input. Validating type, length and format at the
// edge shrinks the attack surface. (SQL injection itself is prevented separately
// with parameterized queries from Phase 4 onward.)
export function validate(req, res, next) {
  const result = validationResult(req);
  if (result.isEmpty()) return next();

  const errors = result.array().map((e) => ({ field: e.path, message: e.msg }));
  return sendError(res, 'Validation failed', 400, errors);
}