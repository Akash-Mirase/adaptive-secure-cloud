// Turns an Axios error OR a plain Error (e.g. a decryption failure, which has
// no HTTP response) into { message, fieldErrors }.
export function parseApiError(err) {
  const body = err?.response?.data;
  if (body) {
    const fieldErrors = {};
    (body.errors || []).forEach((e) => { fieldErrors[e.field] = e.message; });
    return { message: body.message || 'Something went wrong', fieldErrors };
  }
  if (err instanceof Error) return { message: err.message, fieldErrors: {} };
  return { message: 'Cannot reach the server. Is the backend running?', fieldErrors: {} };
}