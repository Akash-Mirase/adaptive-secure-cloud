// Consistent response envelope for the whole API:
// { success: boolean, message: string, data: any }
export function sendSuccess(res, data = null, message = 'OK', status = 200) {
  return res.status(status).json({ success: true, message, data });
}

export function sendError(res, message = 'Error', status = 500) {
  return res.status(status).json({ success: false, message, data: null });
}