// Express 4 does not catch rejected promises in async handlers, so an
// unhandled failure could hang the request or crash the process.
// This wrapper forwards any error to the central error handler.
export default function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}