// Turns an Axios error into { message, fieldErrors } using our API's error envelope.
export function parseApiError(err) {
  const body = err.response?.data;
  if (!body) {
    return { message: 'Cannot reach the server. Is the backend running?', fieldErrors: {} };
  }
  const fieldErrors = {};
  (body.errors || []).forEach((e) => { fieldErrors[e.field] = e.message; });
  return { message: body.message || 'Something went wrong', fieldErrors };
}