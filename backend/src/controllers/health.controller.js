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