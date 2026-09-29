import { query } from '../config/env.js';

// A revoked token is only dangerous until it expires anyway, so rows can be
// purged after expires_at without weakening security.
export async function revoke({ jti, userId, expiresAt }, executor) {
  await query(
    `INSERT INTO revoked_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE jti = jti`,
    [jti, userId, expiresAt],
    executor
  );
}

export async function isRevoked(jti, executor) {
  const rows = await query('SELECT 1 FROM revoked_tokens WHERE jti = ?', [jti], executor);
  return rows.length > 0;
}

export async function purgeExpired(executor) {
  const result = await query('DELETE FROM revoked_tokens WHERE expires_at < UTC_TIMESTAMP()', [], executor);
  return result.affectedRows;
}