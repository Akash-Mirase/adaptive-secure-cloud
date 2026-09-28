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
    keyVersion: r.key_version,
  };

// Everything stored here is either non-secret (salt, iterations, IVs) or
// ciphertext (wrapped keys). The server never holds a usable key.
export async function upsertUserKeys(userId, k, executor) {
  await query(
    `INSERT INTO user_keys
       (user_id, kdf_algorithm, kdf_iterations, kdf_salt, wrapped_master_key, master_key_iv,
        recovery_wrapped_master_key, recovery_iv)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       kdf_algorithm = VALUES(kdf_algorithm), kdf_iterations = VALUES(kdf_iterations),
       kdf_salt = VALUES(kdf_salt), wrapped_master_key = VALUES(wrapped_master_key),
       master_key_iv = VALUES(master_key_iv),
       recovery_wrapped_master_key = VALUES(recovery_wrapped_master_key),
       recovery_iv = VALUES(recovery_iv)`,
    [
      userId,
      k.kdfAlgorithm || 'PBKDF2-SHA256',
      k.kdfIterations,
      k.kdfSalt,
      k.wrappedMasterKey,
      k.masterKeyIv,
      k.recoveryWrappedMasterKey ?? null,
      k.recoveryIv ?? null,
    ],
    executor
  );
}

export async function findUserKeys(userId, executor) {
  const rows = await query('SELECT * FROM user_keys WHERE user_id = ?', [userId], executor);
  return toUserKeys(rows[0]) || null;
}