import { query } from '../config/env.js';

const toLog = (r) => ({
  id: r.id,
  userId: r.user_id,
  eventType: r.event_type,
  fileId: r.file_id,
  ipAddress: r.ip_address,
  result: r.result,
  details: r.details,
  createdAt: r.created_at,
});

// Insert-only. The DB user has no UPDATE/DELETE right on this table.
export async function createLog({ userId, eventType, fileId, ipAddress, result, details }, executor) {
  const r = await query(
    `INSERT INTO audit_logs (user_id, event_type, file_id, ip_address, result, details)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [userId ?? null, eventType, fileId ?? null, ipAddress ?? null, result,
     details ? JSON.stringify(details) : null],
    executor
  );
  return r.insertId;
}

export async function listRecent(limit = 50, executor) {
  // LIMIT cannot be a prepared-statement parameter in every MySQL 8 version, so
  // it is forced to a bounded integer first. Injection is impossible: the
  // value is a Number between 1 and 500, never raw input.
  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 500);
  const rows = await query(
    `SELECT * FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT ${safeLimit}`,
    [],
    executor
  );
  return rows.map(toLog);
}