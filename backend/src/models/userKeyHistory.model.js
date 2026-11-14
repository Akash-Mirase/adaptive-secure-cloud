import { query } from '../config/env.js';

export async function insert({ userId, keyVersion, wrappedKey, wrapIv }, ex) {
  await query(
    'INSERT INTO user_key_history (user_id, key_version, wrapped_key, wrap_iv) VALUES (?, ?, ?, ?)',
    [userId, keyVersion, wrappedKey, wrapIv], ex);
}

export async function listForUser(userId, ex) {
  const rows = await query(
    'SELECT key_version, wrapped_key, wrap_iv FROM user_key_history WHERE user_id = ? ORDER BY key_version ASC',
    [userId], ex);
  return rows.map((r) => ({ keyVersion: r.key_version, wrappedKey: r.wrapped_key, wrapIv: r.wrap_iv }));
}