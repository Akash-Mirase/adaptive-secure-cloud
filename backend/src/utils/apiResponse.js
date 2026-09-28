// Consistent response envelope for the whole API:
// { success: boolean, message: string, data: any, errors?: [{ field, message }] }
export function sendSuccess(res, data = null, message = 'OK', status = 200) {
  return res.status(status).json({ success: true, message, data });
}

export function sendError(res, message = 'Error', status = 500, errors = null) {
  const body = { success: false, message, data: null };
  if (errors) body.errors = errors;
  return res.status(status).json(body);
}