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
// Everyone with any access to this file, for the owner's "manage sharing" view.
export async function listForFileWithUserInfo(fileId, executor) {
  return query(
    `SELECT p.user_id, p.permission, p.created_at, u.name, u.email
       FROM permissions p JOIN users u ON u.id = p.user_id
      WHERE p.file_id = ?
      ORDER BY p.permission DESC, u.name`,
    [fileId], executor
  );
}

// Files shared WITH this user by someone else, joined with file metadata and
// the owner's identity, for the "Shared with me" page.
export async function listSharedWithUser(userId, executor) {
  return query(
    `SELECT f.id, f.original_name, f.mime_type, f.file_size, f.risk_score, f.risk_level, f.iv, f.created_at,
            p.permission, p.created_at AS shared_at,
            owner.name AS owner_name, owner.email AS owner_email
       FROM permissions p
       JOIN files f ON f.id = p.file_id
       JOIN users owner ON owner.id = f.owner_id
      WHERE p.user_id = ? AND f.owner_id <> ? AND f.status = 'ACTIVE'
      ORDER BY p.created_at DESC`,
    [userId, userId], executor
  );
}