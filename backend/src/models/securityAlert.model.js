import { query } from '../config/env.js';

const toAlert = (r) => ({
  id: r.id, userId: r.user_id, rule: r.rule, severity: r.severity, message: r.message,
  details: r.details, restriction: r.restriction, expiresAt: r.expires_at, createdAt: r.created_at,
});

export async function create({ userId, rule, severity, message, details, restriction, expiresAt }, ex) {
  await query(
    `INSERT INTO security_alerts (user_id, rule, severity, message, details, restriction, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, rule, severity, message, details ? JSON.stringify(details) : null, restriction, expiresAt ?? null], ex);
}

export async function existsSince(userId, rule, since, ex) {
  const rows = await query('SELECT 1 FROM security_alerts WHERE user_id = ? AND rule = ? AND created_at >= ? LIMIT 1',
    [userId, rule, since], ex);
  return rows.length > 0;
}

export async function hasActiveRestriction(userId, restriction, ex) {
  const rows = await query(
    'SELECT 1 FROM security_alerts WHERE user_id = ? AND restriction = ? AND expires_at > UTC_TIMESTAMP() LIMIT 1',
    [userId, restriction], ex);
  return rows.length > 0;
}

export async function countEvents(userId, eventType, result, since, ex) {
  const rows = await query(
    'SELECT COUNT(*) AS n FROM audit_logs WHERE user_id = ? AND event_type = ? AND result = ? AND created_at >= ?',
    [userId, eventType, result, since], ex);
  return rows[0].n;
}

export async function list({ userId, page = 1, pageSize = 25 } = {}, ex) {
  const size = Math.min(Math.max(parseInt(pageSize, 10) || 25, 1), 100);
  const offset = (Math.max(parseInt(page, 10) || 1, 1) - 1) * size;
  const where = userId ? 'WHERE user_id = ?' : '';
  const params = userId ? [userId] : [];
  const rows = await query(`SELECT * FROM security_alerts ${where} ORDER BY created_at DESC, id DESC LIMIT ${size} OFFSET ${offset}`, params, ex);
  const [{ total }] = await query(`SELECT COUNT(*) AS total FROM security_alerts ${where}`, params, ex);
  return { alerts: rows.map(toAlert), total };
}