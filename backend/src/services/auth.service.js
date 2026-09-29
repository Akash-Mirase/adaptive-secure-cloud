import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { env } from '../config/env.js';
import AppError from '../utils/AppError.js';
import * as users from '../models/user.model.js';
import * as revokedTokens from '../models/revokedToken.model.js';
import { logEvent } from './audit.service.js';

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

export async function registerUser({ name, email, password }, { ipAddress } = {}) {
  // bcrypt generates a random salt itself and embeds it in the hash string.
  const passwordHash = await bcrypt.hash(password, env.bcryptRounds);

  let userId;
  try {
    userId = await users.createUser({ name, email, passwordHash });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') throw new AppError('Email is already registered', 409);
    throw err;
  }

  await logEvent({ userId, eventType: 'REGISTER', result: 'SUCCESS', ipAddress });
  return toPublicUser(await users.findById(userId));
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

  const token = jwt.sign({}, env.jwt.secret, {
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