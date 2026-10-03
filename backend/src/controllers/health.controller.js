import { sendSuccess, sendError } from '../utils/apiResponse.js';
import { pingDatabase } from '../config/env.js';
import { checkBucketAccess } from '../services/storage.service.js';

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

export async function getS3Health(req, res) {
  try {
    await checkBucketAccess();
    return sendSuccess(res, { status: 'ok' }, 'S3 bucket is reachable');
  } catch (err) {
    console.error('[s3] health check failed:', err.name, err.message);
    return sendError(res, 'S3 unavailable', 503);
  }
}