import { sendSuccess, sendError } from '../utils/apiResponse.js';
import { pingDatabase } from '../config/db.js';


export function getHealth(req, res) {
  return sendSuccess(
    res,
    {
      service: 'adaptive-secure-cloud-backend',
      status: 'ok',
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    },
    'Backend is healthy'
  );
}

// TEMPORARY (removed in Phase 5): echoes back the sanitized input.
export function validationDemo(req, res) {
  const { name, email } = req.body;
  return sendSuccess(res, { name, email }, 'Input is valid');
}

export async function getDbHealth(req, res) {
  try {
    await pingDatabase();
    return sendSuccess(res, { status: 'ok' }, 'Database is reachable');
  } catch (err) {
    // Details go to the server log only; clients get a generic message.
    console.error('[db] health check failed:', err.code || err.message);
    return sendError(res, 'Database unavailable', 503);
  }
}