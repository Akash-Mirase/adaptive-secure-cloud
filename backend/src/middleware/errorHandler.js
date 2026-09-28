import { sendError } from '../utils/apiResponse.js';

export function notFound(req, res) {
  return sendError(res, `Route not found: ${req.method} ${req.originalUrl}`, 404);
}

// Express recognises error handlers by their 4 arguments; keep all four.
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  console.error('[ERROR]', err.message);
  const status = err.status || 500;
  // SECURITY: never leak stack traces or internals to clients.
  const message = status >= 500 ? 'Internal server error' : err.message;
  return sendError(res, message, status);
}