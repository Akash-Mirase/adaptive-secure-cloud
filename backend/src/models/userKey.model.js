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
    publicKey: r.public_key,
    wrappedPrivateKey: r.wrapped_private_key,
    privateKeyIv: r.private_key_iv,
    keyVersion: r.key_version,
  };

export async function createUserKeys(userId, k, executor) {
  await query(
    `INSERT INTO user_keys
       (user_id, kdf_algorithm, kdf_iterations, kdf_salt, wrapped_master_key, master_key_iv,
        recovery_wrapped_master_key, recovery_iv, recovery_key_hash,
        public_key, wrapped_private_key, private_key_iv)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      userId, k.kdfAlgorithm || 'PBKDF2-SHA256', k.kdfIterations, k.kdfSalt,
      k.wrappedMasterKey, k.masterKeyIv,
      k.recoveryWrappedMasterKey ?? null, k.recoveryIv ?? null, k.recoveryKeyHash ?? null,
      k.publicKey, k.wrappedPrivateKey, k.privateKeyIv,
    ],
    executor
  );
}

export async function findUserKeys(userId, executor) {
  const rows = await query('SELECT * FROM user_keys WHERE user_id = ?', [userId], executor);
  return toUserKeys(rows[0]) || null;
}

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

export async function rewrapAfterRecovery(userId, k, executor) {
  // NOTE: wrapped_private_key / private_key_iv are deliberately NOT touched
  // here. They are wrapped under the Master Key, which recovery does not
  // change — only its KEK-wrapping changes. See the Phase 12 scope note.
  await query(
    `UPDATE user_keys
        SET kdf_iterations = ?, kdf_salt = ?, wrapped_master_key = ?, master_key_iv = ?
      WHERE user_id = ?`,
    [k.kdfIterations, k.kdfSalt, k.wrappedMasterKey, k.masterKeyIv, userId],
    executor
  );
}

// Public lookup for the sharing UI: returns the recipient's PUBLIC key only
// (never anything wrapped/private). This is the one place a key leaves the
// context of its own owner, and it is explicitly the non-secret half.
export async function findPublicKeyByEmail(email, executor) {
  const rows = await query(
    `SELECT u.id, u.name, u.email, k.public_key
       FROM users u JOIN user_keys k ON k.user_id = u.id
      WHERE u.email = ?`,
    [email], executor
  );
  if (!rows[0] || !rows[0].public_key) return null;
  return { id: rows[0].id, name: rows[0].name, email: rows[0].email, publicKey: rows[0].public_key };
}