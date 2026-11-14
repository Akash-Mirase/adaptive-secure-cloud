import { query } from '../config/env.js';

const toMfa = (r) => r && {
  userId: r.user_id, secretCiphertext: r.secret_ciphertext, secretIv: r.secret_iv, secretTag: r.secret_tag,
  enabled: r.enabled === 1, lastUsedStep: r.last_used_step, failedAttempts: r.failed_attempts, lockedUntil: r.locked_until,
};

export async function find(userId, ex) {
  const rows = await query('SELECT * FROM user_mfa WHERE user_id = ?', [userId], ex);
  return toMfa(rows[0]) || null;
}

// Caller must have already checked the user is not enabled; this resets any pending enrollment.
export async function upsertPending(userId, { ciphertext, iv, tag }, ex) {
  await query(
    `INSERT INTO user_mfa (user_id, secret_ciphertext, secret_iv, secret_tag, enabled)
     VALUES (?, ?, ?, ?, 0)
     ON DUPLICATE KEY UPDATE secret_ciphertext = VALUES(secret_ciphertext), secret_iv = VALUES(secret_iv),
       secret_tag = VALUES(secret_tag), enabled = 0, last_used_step = NULL, failed_attempts = 0, locked_until = NULL`,
    [userId, ciphertext, iv, tag], ex);
}

export async function enable(userId, ex) {
  await query('UPDATE user_mfa SET enabled = 1 WHERE user_id = ?', [userId], ex);
}

// Atomic replay protection: succeeds only if this time-step is newer than the last accepted one.
export async function claimStep(userId, step, ex) {
  const r = await query(
    'UPDATE user_mfa SET last_used_step = ? WHERE user_id = ? AND (last_used_step IS NULL OR last_used_step < ?)',
    [step, userId, step], ex);
  return r.affectedRows === 1;
}

export async function recordFailure(userId, max, lockUntil, ex) {
  await query(
    `UPDATE user_mfa SET locked_until = IF(failed_attempts + 1 >= ?, ?, locked_until),
            failed_attempts = failed_attempts + 1 WHERE user_id = ?`,
    [max, lockUntil, userId], ex);
}
export async function resetFailures(userId, ex) {
  await query('UPDATE user_mfa SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?', [userId], ex);
}

export async function removeAll(userId, ex) {
  await query('DELETE FROM mfa_recovery_codes WHERE user_id = ?', [userId], ex);
  await query('DELETE FROM user_mfa WHERE user_id = ?', [userId], ex);
}

export async function replaceRecoveryCodes(userId, hashes, ex) {
  await query('DELETE FROM mfa_recovery_codes WHERE user_id = ?', [userId], ex);
  for (const h of hashes) {
    await query('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)', [userId, h], ex);
  }
}
export async function consumeRecoveryCode(userId, hash, ex) {
  const r = await query(
    'UPDATE mfa_recovery_codes SET used_at = UTC_TIMESTAMP() WHERE user_id = ? AND code_hash = ? AND used_at IS NULL',
    [userId, hash], ex);
  return r.affectedRows === 1;
}
export async function countUnusedRecoveryCodes(userId, ex) {
  const rows = await query('SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL', [userId], ex);
  return rows[0].n;
}