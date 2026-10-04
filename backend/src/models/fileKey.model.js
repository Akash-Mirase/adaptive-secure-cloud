import { query } from '../config/env.js';

const toFileKey = (r) =>
  r && {
    id: r.id,
    fileId: r.file_id,
    userId: r.user_id,
    wrappedFek: r.wrapped_fek,
    wrapIv: r.wrap_iv,
    wrapType: r.wrap_type,
  };

// Stores a WRAPPED (encrypted) FEK. Plaintext FEKs never reach the server.
// Upsert, not plain insert: re-sharing with an existing recipient (e.g. to
// change their permission level) must replace their wrapped FEK, not fail on
// the (file_id, user_id) unique constraint from Phase 4.
export async function createFileKey({ fileId, userId, wrappedFek, wrapIv, wrapType }, executor) {
  await query(
    `INSERT INTO file_keys (file_id, user_id, wrapped_fek, wrap_iv, wrap_type) VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE wrapped_fek = VALUES(wrapped_fek), wrap_iv = VALUES(wrap_iv), wrap_type = VALUES(wrap_type)`,
    [fileId, userId, wrappedFek, wrapIv ?? null, wrapType],
    executor
  );
}

export async function findForUser(fileId, userId, executor) {
  const rows = await query(
    'SELECT * FROM file_keys WHERE file_id = ? AND user_id = ?',
    [fileId, userId],
    executor
  );
  return toFileKey(rows[0]) || null;
}

export async function deleteForUser(fileId, userId, executor) {
  await query('DELETE FROM file_keys WHERE file_id = ? AND user_id = ?', [fileId, userId], executor);
}