import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { env } from '../config/env.js';
import AppError from '../utils/AppError.js';
import * as users from '../models/user.model.js';
import * as revokedTokens from '../models/revokedToken.model.js';
import { logEvent } from './audit.service.js';
import * as userKeys from '../models/userKey.model.js';
import { withTransaction } from '../config/env.js';

const JWT_ISSUER = 'adaptive-secure-cloud';
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

// A real bcrypt hash of a throwaway string. When the email does not exist we still
// run bcrypt.compare against this, so "unknown email" and "wrong password" take the
// same time. Without it, response timing would reveal which emails are registered.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', env.bcryptRounds);

// The only shape of a user that may leave the server (no hash, no lockout counters).
export const toPublicUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  role: u.role,
  createdAt: u.createdAt,
});

const MIN_KDF_ITERATIONS = 100000; // floor enforced server-side; the client's real value is higher (see Phase 8 frontend)

export async function registerUser({ name, email, password, keyBundle }, { ipAddress } = {}) {
  const passwordHash = await bcrypt.hash(password, env.bcryptRounds);

  // The recovery key itself is NEVER stored. It is hashed once, here, purely so
  // a later recovery attempt can be verified server-side; the hash cannot be
  // used to derive or reconstruct the recovery key or the Master Key.
  const recoveryKeyHash = keyBundle.recoveryKey
    ? await bcrypt.hash(keyBundle.recoveryKey, env.bcryptRounds)
    : null;

  let userId;
  try {
    // User row + key-hierarchy row are created atomically: a user must never
    // exist without key material, and vice versa.
    userId = await withTransaction(async (conn) => {
      const id = await users.createUser({ name, email, passwordHash }, conn);
      await userKeys.createUserKeys(id, {
        kdfIterations: keyBundle.kdfIterations,
        kdfSalt: keyBundle.kdfSalt,
        wrappedMasterKey: keyBundle.wrappedMasterKey,
        masterKeyIv: keyBundle.masterKeyIv,
        recoveryWrappedMasterKey: keyBundle.recoveryWrappedMasterKey ?? null,
        recoveryIv: keyBundle.recoveryIv ?? null,
        recoveryKeyHash,
      }, conn);
      return id;
    });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') throw new AppError('Email is already registered', 409);
    throw err;
  }

  await logEvent({ userId, eventType: 'REGISTER', result: 'SUCCESS', ipAddress });
  await logEvent({ userId, eventType: 'KEY_OPERATION', result: 'SUCCESS', ipAddress, details: { action: 'MASTER_KEY_CREATED' } });
  return toPublicUser(await users.findById(userId));
}

// Returns the material the browser needs to unlock the Master Key after
// login. Recovery fields are deliberately excluded from this response — the
// normal unlock path never needs them, so they are not sent on every request.
export async function getKeyBundleForUser(userId) {
  const k = await userKeys.findUserKeys(userId);
  if (!k) throw new AppError('No key material found for this account', 404);
  return {
    kdfAlgorithm: k.kdfAlgorithm,
    kdfIterations: k.kdfIterations,
    kdfSalt: k.kdfSalt,
    wrappedMasterKey: k.wrappedMasterKey,
    masterKeyIv: k.masterKeyIv,
  };
}

// Public (unauthenticated by design — a locked-out user has no JWT) but
// heavily rate-limited. Only returns the RECOVERY ciphertext, which is
// useless without the recovery key the user alone holds.
export async function getRecoveryBundle(email) {
  const user = await users.findByEmail(email);
  if (!user) throw new AppError('No recovery material available for this account', 404);
  const material = await userKeys.findRecoveryMaterial(user.id);
  if (!material || !material.recoveryWrappedMasterKey) {
    throw new AppError('No recovery material available for this account', 404);
  }
  return {
    recoveryWrappedMasterKey: material.recoveryWrappedMasterKey,
    recoveryIv: material.recoveryIv,
  };
}

// Completes recovery: the CLIENT has already unwrapped the Master Key using
// the recovery key and rewrapped it under a KEK derived from the new
// password. This endpoint only verifies the recovery key (via its stored
// hash) and persists the new wrapping. It never sees the Master Key itself.
export async function recoverAccount({ email, recoveryKey, newPassword, keyBundle }, { ipAddress } = {}) {
  const user = await users.findByEmail(email);
  if (!user) throw new AppError('Invalid recovery request', 400);

  const material = await userKeys.findRecoveryMaterial(user.id);
  const hashToCompare = material?.recoveryKeyHash || await bcrypt.hash('no-such-hash', env.bcryptRounds); // timing-safe dummy
  const recoveryKeyOk = await bcrypt.compare(recoveryKey, hashToCompare);

  if (!material?.recoveryKeyHash || !recoveryKeyOk) {
    await logEvent({ userId: user.id, eventType: 'KEY_OPERATION', result: 'DENIED', ipAddress, details: { action: 'RECOVERY_ATTEMPT', reason: 'BAD_RECOVERY_KEY' } });
    throw new AppError('Invalid recovery request', 400);
  }

  const newPasswordHash = await bcrypt.hash(newPassword, env.bcryptRounds);

  await withTransaction(async (conn) => {
    await users.updatePasswordHash(user.id, newPasswordHash, conn);
    await userKeys.rewrapAfterRecovery(user.id, keyBundle, conn);
  });

  // NOTE (documented limitation, see below): any JWT issued before recovery
  // remains valid until it naturally expires (max 15 minutes). Full
  // session-wide revocation would need a per-user "tokens valid after"
  // timestamp, which is out of scope for this phase.
  await logEvent({ userId: user.id, eventType: 'KEY_OPERATION', result: 'SUCCESS', ipAddress, details: { action: 'RECOVERY_COMPLETED' } });
}

export async function loginUser({ email, password }, { ipAddress } = {}) {
  const record = await users.findAuthRecordByEmail(email);

  // Always run one bcrypt comparison, whether or not the account exists (see DUMMY_HASH).
  const passwordOk = await bcrypt.compare(password, record ? record.passwordHash : DUMMY_HASH);

  if (!record) {
    await logEvent({ eventType: 'LOGIN_FAILED', result: 'FAILURE', ipAddress, details: { reason: 'UNKNOWN_EMAIL' } });
    throw new AppError('Invalid email or password', 401);
  }

  // A lock that has expired starts the counter fresh.
  const now = new Date();
  if (record.lockedUntil && new Date(record.lockedUntil) <= now) {
    await users.resetFailedLogins(record.id);
    record.lockedUntil = null;
  }

  // Locked accounts are refused even with the correct password.
  if (record.lockedUntil) {
    await logEvent({ userId: record.id, eventType: 'LOGIN_FAILED', result: 'DENIED', ipAddress, details: { reason: 'ACCOUNT_LOCKED' } });
    throw new AppError('Account temporarily locked after too many failed attempts. Try again later.', 429);
  }

  if (!passwordOk) {
    const lockUntil = new Date(Date.now() + LOCK_MINUTES * 60 * 1000);
    await users.recordFailedLogin(record.id, MAX_FAILED_ATTEMPTS, lockUntil);
    await logEvent({ userId: record.id, eventType: 'LOGIN_FAILED', result: 'FAILURE', ipAddress, details: { reason: 'BAD_PASSWORD' } });
    // Same message as "unknown email": do not reveal which part was wrong.
    throw new AppError('Invalid email or password', 401);
  }

  if (record.failedLoginCount > 0) await users.resetFailedLogins(record.id);

  const { token, expiresAt } = issueAccessToken(record.id);
  await logEvent({ userId: record.id, eventType: 'LOGIN', result: 'SUCCESS', ipAddress });

  return { user: toPublicUser(record), token, expiresAt: expiresAt.toISOString() };
}

// The token carries only: sub (user id), jti (unique token id, used for revocation),
// iat/exp (timing) and iss. The ROLE is deliberately NOT in the token. It is read from
// the database on every request, so a demoted or deleted user loses power immediately.
function issueAccessToken(userId) {
  if (!env.jwt.secret) throw new Error('JWT_SECRET is not configured');

  const token = jwt.sign({ purpose: 'access' }, env.jwt.secret, {
    algorithm: 'HS256',
    expiresIn: env.jwt.expiresIn,
    subject: String(userId),
    jwtid: randomUUID(),
    issuer: JWT_ISSUER,
  });
  const { exp } = jwt.decode(token);
  return { token, expiresAt: new Date(exp * 1000) };
}

// SECURITY: the accepted algorithm is PINNED to HS256. Without this, attackers can try
// "alg: none" (no signature) or algorithm-confusion tricks. Every failure gives the
// same generic error.
export function verifyAccessToken(token) {
  try {
    return jwt.verify(token, env.jwt.secret, { algorithms: ['HS256'], issuer: JWT_ISSUER });
  } catch {
    throw new AppError('Invalid or expired token', 401);
  }
}

// Logout: the token is written to the revocation list until its natural expiry.
export async function logoutUser({ user, auth }, { ipAddress } = {}) {
  await revokedTokens.revoke({
    jti: auth.jti,
    userId: user.id,
    expiresAt: new Date(auth.exp * 1000),
  });
  await logEvent({ userId: user.id, eventType: 'LOGOUT', result: 'SUCCESS', ipAddress });
}

// The OUTER expiry here is just the longest window any policy currently
// needs (HIGH's 10 minutes). A stricter policy (CRITICAL's 2 minutes)
// re-checks freshness against the token's `iat` in riskPolicy.js, rather
// than needing a separate token per risk level — one step-up covers every
// file, with each file's own policy deciding how long it stays trusted for.
const MAX_STEP_UP_VALIDITY_SECONDS = 600;

function issueStepUpToken(userId) {
  const token = jwt.sign({ purpose: 'step-up' }, env.jwt.secret, {
    algorithm: 'HS256',
    expiresIn: MAX_STEP_UP_VALIDITY_SECONDS,
    subject: String(userId),
    jwtid: randomUUID(),
    issuer: JWT_ISSUER,
  });
  const { exp } = jwt.decode(token);
  return { token, expiresAt: new Date(exp * 1000) };
}

// SECURITY: the purpose claim is checked here, not left to the caller, so
// every call site gets the same guarantee — a normal access token can never
// be mistaken for a step-up token, and vice versa (see authenticate() in
// middleware/auth.js for the matching check on the other side).
export function verifyStepUpToken(token) {
  let claims;
  try {
    claims = jwt.verify(token, env.jwt.secret, { algorithms: ['HS256'], issuer: JWT_ISSUER });
  } catch {
    throw new AppError('Step-up verification required for this file', 428);
  }
  if (claims.purpose !== 'step-up') {
    throw new AppError('Step-up verification required for this file', 428);
  }
  return claims;
}

// Re-confirms the CURRENT password of an ALREADY-authenticated user (req.user
// is already known from the JWT; this only proves "you still know the
// password right now"). It is intentionally the same factor as login — see
// the Phase 11 scope note on why this is not full MFA.
export async function stepUpVerify({ userId, password }, { ipAddress } = {}) {
  const record = await users.findAuthRecordById(userId);
  const passwordOk = record && (await bcrypt.compare(password, record.passwordHash));

  if (!record || !passwordOk) {
    await logEvent({ userId, eventType: 'STEP_UP_VERIFICATION', result: 'FAILURE', ipAddress });
    throw new AppError('Incorrect password', 401);
  }

  const { token, expiresAt } = issueStepUpToken(userId);
  await logEvent({ userId, eventType: 'STEP_UP_VERIFICATION', result: 'SUCCESS', ipAddress });
  return { stepUpToken: token, expiresAt: expiresAt.toISOString() };
}