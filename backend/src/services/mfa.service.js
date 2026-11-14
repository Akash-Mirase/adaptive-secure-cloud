import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import bcrypt from 'bcrypt';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { env } from '../config/env.js';
import { withTransaction } from '../config/env.js';
import AppError from '../utils/AppError.js';
import * as mfa from '../models/mfa.model.js';
import * as users from '../models/user.model.js';
import { logEvent } from './audit.service.js';

const ISSUER = 'Adaptive Secure Cloud';
const STEP_MS = 30000;
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;
const RECOVERY_COUNT = 10;

// ---- secret-at-rest encryption (server-side; the server must be able to verify codes) ----
function keyBytes() {
  const k = Buffer.from(env.mfaEncryptionKey || '', 'hex');
  if (k.length !== 32) throw new Error('MFA_ENCRYPTION_KEY must be 64 hex characters');
  return k;
}
function encryptSecret(secret, userId) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', keyBytes(), iv);
  c.setAAD(Buffer.from(`mfa:${userId}`)); // binds ciphertext to this user
  const ct = Buffer.concat([c.update(secret, 'utf8'), c.final()]);
  return { ciphertext: ct.toString('base64'), iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64') };
}
function decryptSecret(row, userId) {
  const d = createDecipheriv('aes-256-gcm', keyBytes(), Buffer.from(row.secretIv, 'base64'));
  d.setAAD(Buffer.from(`mfa:${userId}`));
  d.setAuthTag(Buffer.from(row.secretTag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(row.secretCiphertext, 'base64')), d.final()]).toString('utf8');
}

// Returns the matching 30s time-step (checking previous/current/next for clock skew) or null.
function matchStep(secret, code) {
  if (!/^\d{6}$/.test(String(code))) return null;
  const now = Date.now();
  for (const offset of [0, -1, 1]) {
    const epoch = now + offset * STEP_MS;
    if (authenticator.clone({ epoch, window: 0 }).check(String(code), secret)) return Math.floor(epoch / STEP_MS);
  }
  return null;
}

const normalizeRecovery = (c) => String(c).replace(/[\s-]/g, '').toLowerCase();
const hashRecovery = (c) => createHash('sha256').update(normalizeRecovery(c)).digest('hex');

function generateRecoveryCodes() {
  return Array.from({ length: RECOVERY_COUNT }, () => randomBytes(10).toString('hex').match(/.{4}/g).join('-'));
}

async function assertNotLocked(row) {
  if (!row.lockedUntil) return;
  if (new Date(row.lockedUntil) > new Date()) {
    throw new AppError('Too many failed attempts. Try again later.', 429);
  }
  await mfa.resetFailures(row.userId); // lock expired: temporary by design, never permanent
}
async function registerFailure(userId, ipAddress, reason) {
  await mfa.recordFailure(userId, MAX_FAILS, new Date(Date.now() + LOCK_MINUTES * 60000));
  await logEvent({ userId, eventType: 'LOGIN_FAILED', result: 'FAILURE', ipAddress, details: { stage: 'MFA', reason } });
}

// Reauthentication for account-security changes.
async function requirePassword(userId, password, ipAddress) {
  const rec = await users.findAuthRecordById(userId);
  const ok = rec && (await bcrypt.compare(password, rec.passwordHash));
  if (!ok) {
    await logEvent({ userId, eventType: 'KEY_OPERATION', result: 'DENIED', ipAddress, details: { action: 'MFA_REAUTH_FAILED' } });
    throw new AppError('Incorrect password', 401);
  }
}

export async function isEnabled(userId) {
  return Boolean((await mfa.find(userId))?.enabled);
}

export async function getStatus(userId) {
  const row = await mfa.find(userId);
  return { enabled: Boolean(row?.enabled), recoveryCodesRemaining: row?.enabled ? await mfa.countUnusedRecoveryCodes(userId) : 0 };
}

export async function beginEnrollment(user, password, { ipAddress } = {}) {
  await requirePassword(user.id, password, ipAddress);
  if (await isEnabled(user.id)) throw new AppError('MFA is already enabled', 409);
  const secret = authenticator.generateSecret();
  await mfa.upsertPending(user.id, encryptSecret(secret, user.id));
  const otpauthUri = authenticator.keyuri(user.email, ISSUER, secret);
  return { secret, otpauthUri, qrDataUrl: await QRCode.toDataURL(otpauthUri) };
}

export async function confirmEnrollment(userId, code, { ipAddress } = {}) {
  const row = await mfa.find(userId);
  if (!row || row.enabled) throw new AppError('No pending MFA enrollment', 400);
  await assertNotLocked(row);
  const step = matchStep(decryptSecret(row, userId), code);
  if (step === null || !(await mfa.claimStep(userId, step))) {
    await registerFailure(userId, ipAddress, 'BAD_ENROLLMENT_CODE');
    throw new AppError('Invalid authentication code', 401);
  }
  const codes = generateRecoveryCodes();
  await withTransaction(async (conn) => {
    await mfa.enable(userId, conn);
    await mfa.replaceRecoveryCodes(userId, codes.map(hashRecovery), conn);
    await mfa.resetFailures(userId, conn);
  });
  await logEvent({ userId, eventType: 'KEY_OPERATION', result: 'SUCCESS', ipAddress, details: { action: 'MFA_ENABLED' } });
  return { recoveryCodes: codes }; // the ONLY time they are ever shown
}

// Verifies a TOTP code OR a recovery code. Used by MFA login, step-up, disable and regenerate.
export async function verifySecondFactor(userId, { code, recoveryCode } = {}, { ipAddress } = {}) {
  const row = await mfa.find(userId);
  if (!row?.enabled) throw new AppError('MFA is not enabled', 400);
  await assertNotLocked(row);

  let ok = false;
  let method;
  if (recoveryCode) {
    method = 'RECOVERY_CODE';
    ok = await mfa.consumeRecoveryCode(userId, hashRecovery(recoveryCode));
  } else if (code) {
    method = 'TOTP';
    const step = matchStep(decryptSecret(row, userId), code);
    ok = step !== null && (await mfa.claimStep(userId, step));
  } else {
    throw new AppError('Authentication code required', 422);
  }

  if (!ok) {
    await registerFailure(userId, ipAddress, `BAD_${method}`);
    throw new AppError('Invalid authentication code', 401);
  }
  await mfa.resetFailures(userId);
  if (method === 'RECOVERY_CODE') {
    await logEvent({ userId, eventType: 'KEY_OPERATION', result: 'SUCCESS', ipAddress, details: { action: 'MFA_RECOVERY_CODE_USED' } });
  }
  return method;
}

export async function disable(userId, { password, code, recoveryCode }, { ipAddress } = {}) {
  await requirePassword(userId, password, ipAddress);
  await verifySecondFactor(userId, { code, recoveryCode }, { ipAddress });
  await mfa.removeAll(userId);
  await logEvent({ userId, eventType: 'KEY_OPERATION', result: 'SUCCESS', ipAddress, details: { action: 'MFA_DISABLED' } });
}

export async function regenerateRecoveryCodes(userId, { password, code }, { ipAddress } = {}) {
  await requirePassword(userId, password, ipAddress);
  await verifySecondFactor(userId, { code }, { ipAddress }); // TOTP only: recovery codes can't mint new recovery codes
  const codes = generateRecoveryCodes();
  await mfa.replaceRecoveryCodes(userId, codes.map(hashRecovery));
  await logEvent({ userId, eventType: 'KEY_OPERATION', result: 'SUCCESS', ipAddress, details: { action: 'MFA_RECOVERY_CODES_REGENERATED' } });
  return { recoveryCodes: codes };
}