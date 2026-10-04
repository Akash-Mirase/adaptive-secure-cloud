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

// Insert-only. The DB user has no UPDATE/DELETE right on this table (Phase 4).
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
  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 500);
  const rows = await query(`SELECT * FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT ${safeLimit}`, [], executor);
  return rows.map(toLog);
}

// Builds a parameterized WHERE clause from a fixed, known set of columns.
// SECURITY: column names are hard-coded here, never taken from the caller —
// only VALUES (always bound as `?` parameters) come from the request. This
// is what keeps dynamic filtering immune to SQL injection.
function buildFilters({ userId, eventType, result, fileId, dateFrom, dateTo }) {
  const clauses = [];
  const params = [];
  if (userId) { clauses.push('user_id = ?'); params.push(userId); }
  if (eventType) { clauses.push('event_type = ?'); params.push(eventType); }
  if (result) { clauses.push('result = ?'); params.push(result); }
  if (fileId) { clauses.push('file_id = ?'); params.push(fileId); }
  if (dateFrom) { clauses.push('created_at >= ?'); params.push(dateFrom); }
  if (dateTo) { clauses.push('created_at <= ?'); params.push(dateTo); }
  return { whereSql: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

export async function countFiltered(filters, executor) {
  const { whereSql, params } = buildFilters(filters);
  const rows = await query(`SELECT COUNT(*) AS total FROM audit_logs ${whereSql}`, params, executor);
  return rows[0].total;
}

// LIMIT/OFFSET are forced to bounded integers via parseInt + clamp (same
// pattern as listRecent above), never interpolated from a raw request
// string, so this stays injection-safe despite not being a bound parameter.
export async function listFiltered(filters, { page = 1, pageSize = 25 } = {}, executor) {
  const { whereSql, params } = buildFilters(filters);
  const safePageSize = Math.min(Math.max(parseInt(pageSize, 10) || 25, 1), 100);
  const safePage = Math.max(parseInt(page, 10) || 1, 1);
  const offset = (safePage - 1) * safePageSize;
  const rows = await query(
    `SELECT * FROM audit_logs ${whereSql} ORDER BY created_at DESC, id DESC LIMIT ${safePageSize} OFFSET ${offset}`,
    params, executor
  );
  return rows.map(toLog);
}

export async function countByEventType(filters, executor) {
  const { whereSql, params } = buildFilters(filters);
  const rows = await query(`SELECT event_type, COUNT(*) AS count FROM audit_logs ${whereSql} GROUP BY event_type`, params, executor);
  return rows.map((r) => ({ eventType: r.event_type, count: r.count }));
}

export async function countByResult(filters, executor) {
  const { whereSql, params } = buildFilters(filters);
  const rows = await query(`SELECT result, COUNT(*) AS count FROM audit_logs ${whereSql} GROUP BY result`, params, executor);
  return rows.map((r) => ({ result: r.result, count: r.count }));
}