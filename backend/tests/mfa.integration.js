import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import request from 'supertest';
import { authenticator } from 'otplib';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'mfa-test-secret-mfa-test-secret-0000000000';
process.env.MFA_ENCRYPTION_KEY = '00000000000000000000000000000000000000000000000000000000000000aa';
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/env.js');

const PASSWORD = 'correct horse battery staple';
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const b64 = (n) => randomBytes(n).toString('base64');
const codeAt = (secret, offsetSteps = 0) =>
  authenticator.clone({ epoch: Date.now() + offsetSteps * 30000, window: 0 }).generate(secret);

after(async () => {
  await query("DELETE FROM users WHERE email LIKE 'mfatest-%@example.com'");
  await closePool();
});

async function newUser() {
  const email = `mfatest-${randomUUID()}@example.com`;
  await request(app).post('/api/auth/register').send({
    name: 'MFA Tester', email, password: PASSWORD,
    kdfSalt: b64(16), kdfIterations: 250000, wrappedMasterKey: b64(48), masterKeyIv: b64(12),
    recoveryWrappedMasterKey: b64(48), recoveryIv: b64(12), recoveryKey: 'AAAA-BBBB-CCCC-DDDD-EEEE',
    publicKey: b64(294), wrappedPrivateKey: b64(1200), privateKeyIv: b64(12),
  }).expect(201);
  const login = await request(app).post('/api/auth/login').send({ email, password: PASSWORD }).expect(200);
  return { email, token: login.body.data.token, id: login.body.data.user.id };
}
// Replay protection means a step can be used once; tests that need several codes reset it explicitly.
const resetReplay = (id) => query('UPDATE user_mfa SET last_used_step = NULL, failed_attempts = 0, locked_until = NULL WHERE user_id = ?', [id]);

async function enableMfa(u) {
  const enroll = await request(app).post('/api/mfa/enroll').set(bearer(u.token)).send({ password: PASSWORD }).expect(200);
  const secret = enroll.body.data.secret;
  const confirm = await request(app).post('/api/mfa/enroll/confirm').set(bearer(u.token)).send({ code: codeAt(secret) }).expect(201);
  await resetReplay(u.id);
  return { secret, recoveryCodes: confirm.body.data.recoveryCodes };
}

test('enrollment requires the current password', async () => {
  const u = await newUser();
  const res = await request(app).post('/api/mfa/enroll').set(bearer(u.token)).send({ password: 'wrong password here!' });
  assert.equal(res.status, 401);
});

test('enrollment: secret is encrypted at rest, 10 recovery codes issued and stored only as hashes', async () => {
  const u = await newUser();
  const { secret, recoveryCodes } = await enableMfa(u);
  assert.equal(recoveryCodes.length, 10);
  const [row] = await query('SELECT * FROM user_mfa WHERE user_id = ?', [u.id]);
  assert.ok(!row.secret_ciphertext.includes(secret), 'TOTP secret must not be stored in plaintext');
  const stored = (await query('SELECT code_hash FROM mfa_recovery_codes WHERE user_id = ?', [u.id])).map((r) => r.code_hash);
  assert.equal(stored.length, 10);
  for (const c of recoveryCodes) assert.ok(!stored.includes(c.replace(/-/g, '')), 'recovery codes must be hashed');
});

test('login with MFA: password alone yields no session; TOTP completes it; pending token is not an access token', async () => {
  const u = await newUser();
  const { secret } = await enableMfa(u);
  const step1 = await request(app).post('/api/auth/login').send({ email: u.email, password: PASSWORD }).expect(200);
  assert.equal(step1.body.data.mfaRequired, true);
  assert.equal(step1.body.data.token, undefined);

  assert.equal((await request(app).get('/api/auth/me').set(bearer(step1.body.data.mfaToken))).status, 401);

  const step2 = await request(app).post('/api/auth/login/mfa').send({ mfaToken: step1.body.data.mfaToken, code: codeAt(secret) });
  assert.equal(step2.status, 200);
  assert.equal((await request(app).get('/api/auth/me').set(bearer(step2.body.data.token))).status, 200);
});

test('a TOTP code cannot be replayed', async () => {
  const u = await newUser();
  const { secret } = await enableMfa(u);
  const code = codeAt(secret);
  const t1 = (await request(app).post('/api/auth/login').send({ email: u.email, password: PASSWORD })).body.data.mfaToken;
  assert.equal((await request(app).post('/api/auth/login/mfa').send({ mfaToken: t1, code })).status, 200);
  const t2 = (await request(app).post('/api/auth/login').send({ email: u.email, password: PASSWORD })).body.data.mfaToken;
  assert.equal((await request(app).post('/api/auth/login/mfa').send({ mfaToken: t2, code })).status, 401);
});

test('wrong codes are rejected; 5 failures lock MFA temporarily (and the lock is not permanent)', async () => {
  const u = await newUser();
  const { secret } = await enableMfa(u);
  const mfaToken = (await request(app).post('/api/auth/login').send({ email: u.email, password: PASSWORD })).body.data.mfaToken;
  for (let i = 0; i < 5; i += 1) {
    assert.equal((await request(app).post('/api/auth/login/mfa').send({ mfaToken, code: '000000' })).status, 401);
  }
  assert.equal((await request(app).post('/api/auth/login/mfa').send({ mfaToken, code: codeAt(secret) })).status, 429);
  await query('UPDATE user_mfa SET locked_until = ? WHERE user_id = ?', [new Date(Date.now() - 1000), u.id]);
  assert.equal((await request(app).post('/api/auth/login/mfa').send({ mfaToken, code: codeAt(secret) })).status, 200);
});

test('a recovery code works exactly once', async () => {
  const u = await newUser();
  const { recoveryCodes } = await enableMfa(u);
  const login = async () => (await request(app).post('/api/auth/login').send({ email: u.email, password: PASSWORD })).body.data.mfaToken;
  assert.equal((await request(app).post('/api/auth/login/mfa').send({ mfaToken: await login(), recoveryCode: recoveryCodes[0] })).status, 200);
  assert.equal((await request(app).post('/api/auth/login/mfa').send({ mfaToken: await login(), recoveryCode: recoveryCodes[0] })).status, 401);
});


test('step-up for an MFA user needs password AND a code (HIGH/CRITICAL access is now two-factor)', async () => {
  const u = await newUser();
  const { secret } = await enableMfa(u);

  const loginResponse = await request(app)
    .post('/api/auth/login')
    .send({ email: u.email, password: PASSWORD });

  const loginMfaToken = loginResponse.body.data.mfaToken;

  const loginCode = codeAt(secret, 0);

  const loginMfaResponse = await request(app)
    .post('/api/auth/login/mfa')
    .send({
      mfaToken: loginMfaToken,
      code: loginCode,
    });

  assert.equal(loginMfaResponse.status, 200);

  const accessToken = loginMfaResponse.body.data.token;

  // Missing MFA code must be rejected.
  const missingCodeResponse = await request(app)
    .post('/api/auth/step-up')
    .set(bearer(accessToken))
    .send({ password: PASSWORD });

  assert.equal(missingCodeResponse.status, 422);

  // Generate a newer TOTP time step for step-up.
  const stepUpCode = codeAt(secret, 1);

  const stepUpResponse = await request(app)
    .post('/api/auth/step-up')
    .set(bearer(accessToken))
    .send({
      password: PASSWORD,
      mfaCode: stepUpCode,
    });

  assert.equal(stepUpResponse.status, 200);
  assert.ok(stepUpResponse.body.data.stepUpToken);
});


test('disable requires password and a valid code; afterwards login needs no second factor', async () => {
  const u = await newUser();
  const { secret } = await enableMfa(u);
  assert.equal((await request(app).post('/api/mfa/disable').set(bearer(u.token)).send({ password: PASSWORD })).status, 422);
  assert.equal((await request(app).post('/api/mfa/disable').set(bearer(u.token)).send({ password: 'wrong password here!', code: codeAt(secret) })).status, 401);
  await request(app).post('/api/mfa/disable').set(bearer(u.token)).send({ password: PASSWORD, code: codeAt(secret) }).expect(200);
  const login = await request(app).post('/api/auth/login').send({ email: u.email, password: PASSWORD }).expect(200);
  assert.ok(login.body.data.token);
});

test('MFA events are audited without secrets or codes', async () => {
  const u = await newUser();
  await enableMfa(u);
  const rows = await query("SELECT details FROM audit_logs WHERE user_id = ? AND event_type = 'KEY_OPERATION'", [u.id]);
  assert.ok(rows.some((r) => r.details?.action === 'MFA_ENABLED'));
  assert.ok(!JSON.stringify(rows).match(/secret|recoveryCodes|\d{6}/i));
});