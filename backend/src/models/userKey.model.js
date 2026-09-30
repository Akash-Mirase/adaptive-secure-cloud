import { query } from '../config/env.js';

const toUserKeys = (r) =>
  r && {
    userId: r.user_id,
    kdfAlgorithm: r.kdf_algorithm,
    kdfIterations: r.kdf_iterations,
    kdfSalt: r.kdf_salt,
    wrappedMasterKey: r.wrapped_master_key,
    masterKeyIv: r.master_key_iv,
    recoveryWrappedMasterKey: r.recovery_wrapped_master_key,
    recoveryIv: r.recovery_iv,
    hasRecoveryKeyHash: r.recovery_key_hash !== null,
    keyVersion: r.key_version,
  };

export async function createUserKeys(userId, k, executor) {
  await query(
    `INSERT INTO user_keys
       (user_id, kdf_algorithm, kdf_iterations, kdf_salt, wrapped_master_key, master_key_iv,
        recovery_wrapped_master_key, recovery_iv, recovery_key_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      userId, k.kdfAlgorithm || 'PBKDF2-SHA256', k.kdfIterations, k.kdfSalt,
      k.wrappedMasterKey, k.masterKeyIv,
      k.recoveryWrappedMasterKey ?? null, k.recoveryIv ?? null, k.recoveryKeyHash ?? null,
    ],
    executor
  );
}

export async function findUserKeys(userId, executor) {
  const rows = await query('SELECT * FROM user_keys WHERE user_id = ?', [userId], executor);
  return toUserKeys(rows[0]) || null;
}

// Only the recovery service needs the actual hash and the recovery ciphertext.
export async function findRecoveryMaterial(userId, executor) {
  const rows = await query(
    'SELECT recovery_wrapped_master_key, recovery_iv, recovery_key_hash FROM user_keys WHERE user_id = ?',
    [userId], executor
  );
  if (!rows[0]) return null;
  return {
    recoveryWrappedMasterKey: rows[0].recovery_wrapped_master_key,
    recoveryIv: rows[0].recovery_iv,
    recoveryKeyHash: rows[0].recovery_key_hash,
  };
}

// Used after a successful recovery: the Master Key stays the SAME (it was
// unwrapped client-side with the recovery key), only its KEK-wrapping changes
// because the password changed. Recovery material is untouched.
export async function rewrapAfterRecovery(userId, k, executor) {
  await query(
    `UPDATE user_keys
        SET kdf_iterations = ?, kdf_salt = ?, wrapped_master_key = ?, master_key_iv = ?
      WHERE user_id = ?`,
    [k.kdfIterations, k.kdfSalt, k.wrappedMasterKey, k.masterKeyIv, userId],
    executor
  );
}