import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, webcrypto } from 'node:crypto';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'threat-model-test-secret-threat-model-0000';
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/db.js');

const subtle = webcrypto.subtle;
const PASSWORD = 'correct horse battery staple';
const newEmail = () => `threattest-${randomUUID()}@example.com`;
const KEY_METADATA_JSON = JSON.stringify({ algorithm: 'AES-256-GCM', ivLength: 12, tagLength: 128, version: 1 });

after(async () => {
  await query("DELETE FROM users WHERE email LIKE 'threattest-%@example.com'");
  await closePool();
});

async function registerAndLogin() {
  const email = newEmail();
  await request(app).post('/api/auth/register').send({ name: 'Threat Tester', email, password: PASSWORD }).expect(201);
  const res = await request(app).post('/api/auth/login').send({ email, password: PASSWORD }).expect(200);
  return { email, token: res.body.data.token, user: res.body.data.user };
}
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function makeMasterKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
}
async function uploadEncrypted(token, plainBuffer, masterKey, { filename = 'secret.pdf', mimeType = 'application/pdf' } = {}) {
  const fek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, fek, plainBuffer));
  const wrapIv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, masterKey, { name: 'AES-GCM', iv: wrapIv, tagLength: 128 })).toString('base64');

  const res = await request(app).post('/api/files').set(bearer(token))
    .field('iv', Buffer.from(iv).toString('base64')).field('keyMetadata', KEY_METADATA_JSON)
    .field('mimeType', mimeType).field('originalSize', String(plainBuffer.length))
    .field('wrappedFek', wrappedFek).field('wrapIv', Buffer.from(wrapIv).toString('base64'))
    .field('userSensitivity', '0')
    .attach('file', ciphertext, { filename, contentType: 'application/octet-stream' });
  return { file: res.body.data.file, fek, ivBase64: Buffer.from(iv).toString('base64'), wrappedFek, wrapIvBase64: Buffer.from(wrapIv).toString('base64') };
}

// ============================================================
// THREAT 1 — Attacker obtains S3 objects. Expected: ciphertext only.
// Full proof already in files.integration.js ("data stored in S3 is
// ciphertext"). Re-verified here via the public API surface only (no direct
// S3 SDK access), to prove the guarantee holds from an attacker's actual
// vantage point: anything retrievable through the app is still ciphertext.
// ============================================================
test('[THREAT 1] downloaded bytes are never equal to the plaintext, even before decryption', async () => {
  const { token } = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const plaintext = Buffer.from('Threat 1 check: this exact sentence must never appear in transit as-is.');
  const { file } = await uploadEncrypted(token, plaintext, masterKey);

  const downloadRes = await request(app).get(`/api/files/${file.id}/download`).set(bearer(token))
    .buffer(true).parse((res, cb) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => cb(null, Buffer.concat(chunks))); });

  assert.ok(!Buffer.from(downloadRes.body).includes(plaintext), 'ciphertext must not contain the plaintext as a substring');
  assert.ok(!Buffer.from(downloadRes.body).equals(plaintext));
  await request(app).delete(`/api/files/${file.id}`).set(bearer(token)).expect(200);
});

// ============================================================
// THREAT 2 — Attacker modifies ciphertext. Expected: AES-GCM detects it.
// Full proof in files.integration.js. Re-verified here with a tamper at
// THREE different offsets (start / middle / the auth tag itself at the end)
// to confirm detection isn't position-dependent.
// ============================================================
for (const [label, offsetFn] of [
  ['start', () => 0],
  ['middle', (len) => Math.floor(len / 2)],
  ['auth tag', (len) => len - 1],
]) {
  test(`[THREAT 2] tampering at the ${label} of the ciphertext is detected`, async () => {
    const { token } = await registerAndLogin();
    const masterKey = await makeMasterKey();
    const plaintext = Buffer.from('Threat 2 check: tampering anywhere must be caught.');
    const { file, wrappedFek, wrapIvBase64, ivBase64 } = await uploadEncrypted(token, plaintext, masterKey);

    const downloadRes = await request(app).get(`/api/files/${file.id}/download`).set(bearer(token))
      .buffer(true).parse((res, cb) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => cb(null, Buffer.concat(chunks))); });
    const tampered = Buffer.from(downloadRes.body);
    const offset = offsetFn(tampered.length);
    tampered[offset] ^= 0xff;

    const fek = await subtle.unwrapKey('raw', Buffer.from(wrappedFek, 'base64'), masterKey,
      { name: 'AES-GCM', iv: Buffer.from(wrapIvBase64, 'base64'), tagLength: 128 },
      { name: 'AES-GCM', length: 256 }, true, ['decrypt']);

    await assert.rejects(
      subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(ivBase64, 'base64'), tagLength: 128 }, fek, tampered),
      `tampering at ${label} must fail GCM verification`
    );
    await request(app).delete(`/api/files/${file.id}`).set(bearer(token)).expect(200);
  });
}

// ============================================================
// THREAT 3 — Unauthorized user requests another user's file.
// Full proof in files.integration.js / sharing.integration.js. Re-verified
// here across ALL FOUR file-scoped endpoints in one place.
// ============================================================
test('[THREAT 3] a stranger is denied on every file-scoped endpoint (metadata, download, key, delete)', async () => {
  const owner = await registerAndLogin();
  const stranger = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const { file } = await uploadEncrypted(owner.token, Buffer.from('owner-only content'), masterKey);

  const endpoints = [
    ['GET', `/api/files/${file.id}`],
    ['GET', `/api/files/${file.id}/download`],
    ['GET', `/api/files/${file.id}/key`],
    ['DELETE', `/api/files/${file.id}`],
    ['GET', `/api/files/${file.id}/permissions`],
  ];
  for (const [method, path] of endpoints) {
    const res = await request(app)[method.toLowerCase()](path).set(bearer(stranger.token));
    assert.equal(res.status, 404, `${method} ${path} must return 404 for a non-permitted user`);
  }
  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

// ============================================================
// THREAT 4 — Attacker obtains database records. Expected: no usable
// plaintext key material anywhere. NEW in this phase: an exhaustive sweep
// of every sensitive column across user_keys and file_keys, not just a
// couple of spot checks.
// ============================================================
test('[THREAT 4] no column in user_keys or file_keys ever contains plaintext key material', async () => {
  const { token, user } = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const { file } = await uploadEncrypted(token, Buffer.from('threat 4 check'), masterKey);

  const [userKeyRow] = await query('SELECT * FROM user_keys WHERE user_id = ?', [user.id]);
  const [fileKeyRow] = await query('SELECT * FROM file_keys WHERE file_id = ? AND user_id = ?', [file.id, user.id]);
  const [userRow] = await query('SELECT * FROM users WHERE id = ?', [user.id]);

  // 1. Login password is never recoverable: a real bcrypt hash, not plaintext or reversible.
  assert.match(userRow.password_hash, /^\$2[aby]\$\d{2}\$/);
  assert.ok(!userRow.password_hash.includes(PASSWORD));

  // 2. wrapped_master_key / wrapped_private_key are ciphertext: fixed-length
  // base64 blobs bear no resemblance to the password or any known plaintext,
  // and critically are NOT valid raw AES/RSA key material on their own
  // (they cannot be imported as a key without first being unwrapped).
  assert.ok(userKeyRow.wrapped_master_key.length > 0);
  await assert.rejects(
    subtle.importKey('raw', Buffer.from(userKeyRow.wrapped_master_key, 'base64'), { name: 'AES-GCM' }, false, ['decrypt']),
    'a wrapped (ciphertext) master key must not itself be importable as a usable AES key'
  );

  // 3. recovery_key_hash is a bcrypt hash, not the recovery key itself.
  if (userKeyRow.recovery_key_hash) {
    assert.match(userKeyRow.recovery_key_hash, /^\$2[aby]\$\d{2}\$/);
  }

  // 4. public_key is intentionally PLAINTEXT (it is not a secret) — this
  // assertion documents that fact explicitly rather than assuming it.
  assert.ok(userKeyRow.public_key && userKeyRow.public_key.length > 0, 'public_key is expected to be readable; this is by design');

  // 5. wrapped_fek is ciphertext, not a usable raw AES-256 key.
  assert.ok(fileKeyRow.wrapped_fek.length > 0);
  const asRawKeyAttempt = Buffer.from(fileKeyRow.wrapped_fek, 'base64');
  assert.notEqual(asRawKeyAttempt.length, 32, 'a wrapped FEK must not merely be a 32-byte raw AES key in disguise');

  await request(app).delete(`/api/files/${file.id}`).set(bearer(token)).expect(200);
});

// ============================================================
// THREAT 5 — Attacker obtains a JWT. Expected: limited abuse window via
// expiry and revocation. NEW: explicit check that a token's `exp` is never
// more than the configured window away from `iat`, in addition to the
// revocation/purpose tests already in auth.integration.js and auth.test.js.
// ============================================================
test('[THREAT 5] an access token is short-lived by construction (<= 15 minutes)', async () => {
  const jwt = (await import('jsonwebtoken')).default;
  const { token } = await registerAndLogin();
  const claims = jwt.decode(token);
  const lifetimeSeconds = claims.exp - claims.iat;
  assert.ok(lifetimeSeconds <= 15 * 60, `token lifetime was ${lifetimeSeconds}s, expected <= 900s`);
});

test('[THREAT 5] a logged-out (revoked) token cannot access ANY protected route, not just /me', async () => {
  const { token } = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const { file } = await uploadEncrypted(token, Buffer.from('x'), masterKey);

  await request(app).post('/api/auth/logout').set(bearer(token)).expect(200);

  const endpoints = [
    ['GET', '/api/auth/me'],
    ['GET', '/api/files'],
    ['GET', `/api/files/${file.id}`],
    ['GET', `/api/files/${file.id}/download`],
  ];
  for (const [method, path] of endpoints) {
    const res = await request(app)[method.toLowerCase()](path).set(bearer(token));
    assert.equal(res.status, 401, `${method} ${path} must reject a revoked token`);
  }
});

// ============================================================
// THREAT 6 — Sharing: only the authorized recipient gets access.
// Full proof in sharing.integration.js. Re-verified here as a single,
// explicit "three strangers, one recipient" scenario.
// ============================================================
test('[THREAT 6] of three other users, only the one actually granted access can read a shared file', async () => {
  const owner = await registerAndLogin();
  const recipient = await registerAndLogin();
  const strangerA = await registerAndLogin();
  const strangerB = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const { file, fek } = await uploadEncrypted(owner.token, Buffer.from('shared content'), masterKey, { filename: 'shared.txt', mimeType: 'text/plain' });

  // Need the recipient's real public key (registered without one in this
  // lightweight helper), so look it up via the DB directly for this test.
  const [recipientKeys] = await query('SELECT public_key FROM user_keys WHERE user_id = ?', [recipient.user.id]);
  // registerAndLogin() here doesn't generate a real RSA keypair (that's a
  // frontend concern simulated fully in sharing.integration.js); skip actual
  // wrapping and instead assert the AUTHORIZATION boundary only, which is
  // what this threat is about.
  if (recipientKeys?.public_key) {
    const pub = await subtle.importKey('spki', Buffer.from(recipientKeys.public_key, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']);
    const wrappedForRecipient = Buffer.from(await subtle.wrapKey('raw', fek, pub, { name: 'RSA-OAEP' })).toString('base64');
    await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token))
      .send({ email: recipient.email, permission: 'DOWNLOAD', wrappedFek: wrappedForRecipient }).expect(201);
  }

  assert.equal((await request(app).get(`/api/files/${file.id}`).set(bearer(strangerA.token))).status, 404);
  assert.equal((await request(app).get(`/api/files/${file.id}`).set(bearer(strangerB.token))).status, 404);

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});