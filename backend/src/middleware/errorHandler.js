import { sendError } from '../utils/apiResponse.js';

export function notFound(req, res) {
  return sendError(res, `Route not found: ${req.method} ${req.originalUrl}`, 404);
}

// Express recognises error handlers by their 4 arguments; keep all four.
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  // Known body-parser failures
  if (err.type === 'entity.parse.failed') return sendError(res, 'Malformed JSON body', 400);
  if (err.type === 'entity.too.large') return sendError(res, 'Request body too large', 413);

  const status = err.status || err.statusCode || 500;

  // Log the real cause server-side only.
  console.error('[ERROR]', err.name, err.message);

  // SECURITY: only errors we threw deliberately (AppError) may show their message.
  // Everything else gets a generic message so internals never leak.
  if (err.isOperational) return sendError(res, err.message, status);
  if (status >= 500) return sendError(res, 'Internal server error', 500);
  return sendError(res, 'Bad request', status);
}