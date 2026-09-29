import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, webcrypto } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'files-test-secret-files-test-secret-000000';
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/env.js');

const subtle = webcrypto.subtle;
const PASSWORD = 'correct horse battery staple';
const newEmail = () => `filetest-${randomUUID()}@example.com`;
const KEY_METADATA_JSON = JSON.stringify({ algorithm: 'AES-256-GCM', ivLength: 12, tagLength: 128, version: 1 });

after(async () => {
  await query("DELETE FROM users WHERE email LIKE 'filetest-%@example.com'");
  await closePool();
});

async function registerAndLogin() {
  const email = newEmail();
  await request(app).post('/api/auth/register').send({ name: 'File Tester', email, password: PASSWORD }).expect(201);
  const res = await request(app).post('/api/auth/login').send({ email, password: PASSWORD }).expect(200);
  return { token: res.body.data.token, user: res.body.data.user };
}
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

// Stands in for the browser's crypto module.
async function encryptForTest(plainBuffer) {
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plainBuffer));
  const rawKey = Buffer.from(await subtle.exportKey('raw', key));
  return { ciphertext, iv, ivBase64: Buffer.from(iv).toString('base64'), keyBase64: rawKey.toString('base64') };
}

async function decryptForTest(ciphertextBuffer, ivBase64, keyBase64) {
  const key = await subtle.importKey('raw', Buffer.from(keyBase64, 'base64'), { name: 'AES-GCM' }, true, ['decrypt']);
  const iv = Buffer.from(ivBase64, 'base64');
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertextBuffer);
  return Buffer.from(plain);
}

async function uploadEncrypted(token, plainBuffer, { filename = 'secret.pdf', mimeType = 'application/pdf', overrides = {} } = {}) {
  const enc = await encryptForTest(plainBuffer);
  const fields = {
    iv: enc.ivBase64,
    keyMetadata: KEY_METADATA_JSON,
    mimeType,
    originalSize: String(plainBuffer.length),
    ...overrides,
  };
  let req = request(app).post('/api/files').set(bearer(token));
  for (const [k, v] of Object.entries(fields)) req = req.field(k, v);
  const res = await req.attach('file', enc.ciphertext, { filename, contentType: 'application/octet-stream' });
  return { res, enc };
}

test('upload requires authentication', async () => {
  const res = await request(app).post('/api/files').attach('file', Buffer.from('hi'), 'note.txt');
  assert.equal(res.status, 401);
});

test('full pipeline: encrypt, upload, list, download, decrypt matches original, then delete', async () => {
  const { token } = await registerAndLogin();
  const plaintext = Buffer.from('This is the real content of a confidential test file.');

  const { res: uploadRes, enc } = await uploadEncrypted(token, plaintext);
  assert.equal(uploadRes.status, 201);
  const file = uploadRes.body.data.file;
  assert.equal(file.encryptionAlgorithm, 'AES-256-GCM');
  assert.equal(file.encryptionPending, false);
  assert.equal(file.fileSize, plaintext.length);
  assert.equal(file.encryptedSize, plaintext.length + 16); // + GCM tag
  assert.equal(file.iv, enc.ivBase64);

  assert.ok((await request(app).get('/api/files').set(bearer(token))).body.data.files.some((f) => f.id === file.id));

  const downloadRes = await request(app)
    .get(`/api/files/${file.id}/download`).set(bearer(token)).buffer(true)
    .parse((res, cb) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => cb(null, Buffer.concat(chunks))); });
  assert.equal(downloadRes.status, 200);
  const ciphertextFromServer = Buffer.from(downloadRes.body);

  // Prove the server gave us CIPHERTEXT (not the plaintext) ...
  assert.ok(!ciphertextFromServer.equals(plaintext));
  // ... and that decrypting it with the real key/IV recovers the exact original bytes.
  const decrypted = await decryptForTest(ciphertextFromServer, enc.ivBase64, enc.keyBase64);
  assert.ok(decrypted.equals(plaintext), 'decrypted bytes must exactly match the original plaintext');

  await request(app).delete(`/api/files/${file.id}`).set(bearer(token)).expect(200);
});

test('data stored on disk is ciphertext, never plaintext', async () => {
  const { token, user } = await registerAndLogin();
  const plaintext = Buffer.from('Sensitive on-disk content check.');
  const { res: uploadRes } = await uploadEncrypted(token, plaintext);
  const file = uploadRes.body.data.file;

  const onDiskPath = path.resolve(process.cwd(), 'storage', 'users', String(user.id), 'files', file.id);
  const onDiskBytes = await fs.readFile(onDiskPath);

  assert.equal(onDiskBytes.length, plaintext.length + 16);
  assert.ok(!onDiskBytes.includes(plaintext), 'plaintext bytes must not appear in the stored object');

  await request(app).delete(`/api/files/${file.id}`).set(bearer(token)).expect(200);
});

test('tamper detection: a modified ciphertext byte fails AES-GCM authentication', async () => {
  const { token } = await registerAndLogin();
  const plaintext = Buffer.from('Content that must not be silently corrupted.');
  const { res: uploadRes, enc } = await uploadEncrypted(token, plaintext);
  const file = uploadRes.body.data.file;

  const downloadRes = await request(app)
    .get(`/api/files/${file.id}/download`).set(bearer(token)).buffer(true)
    .parse((res, cb) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => cb(null, Buffer.concat(chunks))); });
  const tampered = Buffer.from(downloadRes.body);
  tampered[0] ^= 0xff; // flip one bit of ciphertext

  await assert.rejects(
    decryptForTest(tampered, enc.ivBase64, enc.keyBase64),
    'tampered ciphertext must fail GCM tag verification'
  );

  await request(app).delete(`/api/files/${file.id}`).set(bearer(token)).expect(200);
});

test('tamper detection: the wrong key fails AES-GCM authentication', async () => {
  const { token } = await registerAndLogin();
  const plaintext = Buffer.from('Another confidential payload.');
  const { res: uploadRes, enc } = await uploadEncrypted(token, plaintext);
  const file = uploadRes.body.data.file;

  const downloadRes = await request(app)
    .get(`/api/files/${file.id}/download`).set(bearer(token)).buffer(true)
    .parse((res, cb) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => cb(null, Buffer.concat(chunks))); });

  const wrongKeyBytes = Buffer.from(await subtle.exportKey('raw', await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])));
  await assert.rejects(
    decryptForTest(Buffer.from(downloadRes.body), enc.ivBase64, wrongKeyBytes.toString('base64')),
    'decrypting with the wrong key must fail'
  );

  await request(app).delete(`/api/files/${file.id}`).set(bearer(token)).expect(200);
});

test("a user cannot access another user's file (404, not 403)", async () => {
  const owner = await registerAndLogin();
  const stranger = await registerAndLogin();

  const { res: uploadRes } = await uploadEncrypted(owner.token, Buffer.from('private'), { filename: 'secret.txt', mimeType: 'text/plain' });
  const fileId = uploadRes.body.data.file.id;

  assert.equal((await request(app).get(`/api/files/${fileId}`).set(bearer(stranger.token))).status, 404);
  assert.equal((await request(app).get(`/api/files/${fileId}/download`).set(bearer(stranger.token))).status, 404);
  assert.equal((await request(app).delete(`/api/files/${fileId}`).set(bearer(stranger.token))).status, 404);

  await request(app).delete(`/api/files/${fileId}`).set(bearer(owner.token)).expect(200);
});

test('validation: missing iv/keyMetadata is rejected', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).post('/api/files').set(bearer(token))
    .field('mimeType', 'text/plain').field('originalSize', '5')
    .attach('file', Buffer.from('hello'), { filename: 'x.txt', contentType: 'application/octet-stream' });
  assert.equal(res.status, 400);
});

test('validation: IV of the wrong length is rejected', async () => {
  const { token } = await registerAndLogin();
  const { res } = await uploadEncrypted(token, Buffer.from('hello'), { overrides: { iv: Buffer.alloc(8).toString('base64') } });
  assert.equal(res.status, 400);
});

test('validation: wrong declared algorithm is rejected', async () => {
  const { token } = await registerAndLogin();
  const { res } = await uploadEncrypted(token, Buffer.from('hello'), {
    overrides: { keyMetadata: JSON.stringify({ algorithm: 'AES-128-CBC', tagLength: 128 }) },
  });
  assert.equal(res.status, 400);
});

test('validation: ciphertext/size mismatch is rejected', async () => {
  const { token } = await registerAndLogin();
  const { res } = await uploadEncrypted(token, Buffer.from('hello'), { overrides: { originalSize: '999' } });
  assert.equal(res.status, 400);
});

test('invalid file id format returns 400', async () => {
  const { token } = await registerAndLogin();
  assert.equal((await request(app).get('/api/files/not-a-uuid').set(bearer(token))).status, 400);
});

test('disallowed file type is rejected with 415', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).post('/api/files').set(bearer(token))
    .attach('file', Buffer.from('fake exe bytes'), { filename: 'virus.exe', contentType: 'application/x-msdownload' });
  assert.equal(res.status, 415);
});