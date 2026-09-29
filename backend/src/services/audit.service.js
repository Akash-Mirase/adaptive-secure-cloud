import * as auditLogs from '../models/auditLog.model.js';

// Writes one audit event.
// DESIGN CHOICE: if the log write fails we report it on the console and let the
// request continue (fail-open) so a logging problem cannot lock everyone out.
// For CRITICAL-file operations, Phases 11 and 13 will make logging mandatory (fail-closed).
// SECURITY: never put passwords, tokens or keys in `details`.
export async function logEvent({ userId, eventType, fileId, result, ipAddress, details }) {
  try {
    await auditLogs.createLog({ userId, eventType, fileId, result, ipAddress, details });
  } catch (err) {
    console.error('[audit] failed to write log:', err.code || err.message);
  }
}