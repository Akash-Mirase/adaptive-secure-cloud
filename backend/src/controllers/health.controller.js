import { sendSuccess } from '../utils/apiResponse.js';

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