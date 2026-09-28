import { query } from '../config/env.js';

const toPermission = (r) =>
  r && {
    id: r.id,
    fileId: r.file_id,
    userId: r.user_id,
    permission: r.permission,
    grantedBy: r.granted_by,
    createdAt: r.created_at,
  };

// Granting again simply changes the level (one row per file+user).
export async function grant({ fileId, userId, permission, grantedBy }, executor) {
  await query(
    `INSERT INTO permissions (file_id, user_id, permission, granted_by) VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE permission = VALUES(permission), granted_by = VALUES(granted_by)`,
    [fileId, userId, permission, grantedBy ?? null],
    executor
  );
}

export async function find(fileId, userId, executor) {
  const rows = await query(
    'SELECT * FROM permissions WHERE file_id = ? AND user_id = ?',
    [fileId, userId],
    executor
  );
  return toPermission(rows[0]) || null;
}

export async function revoke(fileId, userId, executor) {
  const result = await query(
    'DELETE FROM permissions WHERE file_id = ? AND user_id = ?',
    [fileId, userId],
    executor
  );
  return result.affectedRows === 1;
}

export async function listForFile(fileId, executor) {
  const rows = await query('SELECT * FROM permissions WHERE file_id = ?', [fileId], executor);
  return rows.map(toPermission);
}