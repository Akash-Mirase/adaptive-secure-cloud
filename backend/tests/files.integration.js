import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import request from 'supertest';
import crypto from 'node:crypto';

const { webcrypto } = crypto;

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

  const encoder = new TextEncoder();

  // Same values/algorithms as frontend/src/crypto/kdf.js
  const kdfIterations = 250000;
  const salt = webcrypto.getRandomValues(new Uint8Array(16));

  // Derive the password KEK using PBKDF2-SHA256.
  const passwordKey = await subtle.importKey(
    'raw',
    encoder.encode(PASSWORD),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const kek = await subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: kdfIterations,
      hash: 'SHA-256',
    },
    passwordKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['wrapKey', 'unwrapKey']
  );

  // Same as frontend generateMasterKey()
  const masterKey = await subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['wrapKey', 'unwrapKey']
  );

  // Same as frontend generateWrapIV()
  const masterKeyIv = webcrypto.getRandomValues(
    new Uint8Array(12)
  );

  // Same as frontend wrapMasterKey()
  const wrappedMasterKeyBuffer = await subtle.wrapKey(
    'raw',
    masterKey,
    kek,
    {
      name: 'AES-GCM',
      iv: masterKeyIv,
      tagLength: 128,
    }
  );

  // Same as frontend generateRecoveryKey()
  const recoveryBytes = webcrypto.getRandomValues(
    new Uint8Array(20)
  );

  const recoveryKeyBase64Url = Buffer.from(recoveryBytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const recoveryKey = recoveryKeyBase64Url
    .match(/.{1,4}/g)
    .join('-')
    .toUpperCase();

  // Same as frontend importRecoveryWrapKey():
  // SHA-256(recovery-key raw bytes) -> AES-256-GCM key
  const recoveryHash = await subtle.digest(
    'SHA-256',
    recoveryBytes
  );

  const recoveryWrapKey = await subtle.importKey(
    'raw',
    recoveryHash,
    {
      name: 'AES-GCM',
    },
    false,
    ['wrapKey', 'unwrapKey']
  );

  const recoveryIv = webcrypto.getRandomValues(
    new Uint8Array(12)
  );

  const recoveryWrappedMasterKeyBuffer = await subtle.wrapKey(
    'raw',
    masterKey,
    recoveryWrapKey,
    {
      name: 'AES-GCM',
      iv: recoveryIv,
      tagLength: 128,
    }
  );

  const toBase64 = (value) =>
    Buffer.from(value).toString('base64');

  const registrationPayload = {
    name: 'File Tester',
    email,
    password: PASSWORD,

    kdfSalt: toBase64(salt),
    kdfIterations,

    wrappedMasterKey: toBase64(wrappedMasterKeyBuffer),
    masterKeyIv: toBase64(masterKeyIv),

    recoveryWrappedMasterKey: toBase64(
      recoveryWrappedMasterKeyBuffer
    ),
    recoveryIv: toBase64(recoveryIv),

    recoveryKey,
  };

  const registerResponse = await request(app)
    .post('/api/auth/register')
    .send(registrationPayload)
    .expect(201);

  if (!registerResponse.body?.success) {
    throw new Error(
      `Registration failed: ${JSON.stringify(registerResponse.body)}`
    );
  }

  const res = await request(app)
    .post('/api/auth/login')
    .send({
      email,
      password: PASSWORD,
    })
    .expect(200);

  return {
    token: res.body.data.token,
    user: res.body.data.user,
  };
}
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

// Stands in for the browser's crypto module.
async function encryptForTest(plainBuffer) {
  // Generate the FEK exactly like frontend generateFileKey()
  const fek = await subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // Generate file IV exactly like frontend generateIV()
  const iv = webcrypto.getRandomValues(new Uint8Array(12));

  // Encrypt plaintext with FEK
  const ciphertext = Buffer.from(
    await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
      },
      fek,
      plainBuffer
    )
  );

  // Generate the user's Master Key.
  // This stands in for the Master Key created during registration.
  const masterKey = await subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['wrapKey', 'unwrapKey']
  );

  // Generate FEK wrapping IV exactly like frontend generateWrapIV()
  const wrapIv = webcrypto.getRandomValues(
    new Uint8Array(12)
  );

  // Wrap FEK under Master Key exactly like frontend wrapFek()
  const wrappedFekBuffer = await subtle.wrapKey(
    'raw',
    fek,
    masterKey,
    {
      name: 'AES-GCM',
      iv: wrapIv,
      tagLength: 128,
    }
  );

  // Export FEK for test-side verification.
  const rawFek = Buffer.from(
    await subtle.exportKey('raw', fek)
  );

  // Export Master Key so tests can reproduce the client-side
  // unwrap/decrypt operation.
  const rawMasterKey = Buffer.from(
    await subtle.exportKey('raw', masterKey)
  );

  return {
    ciphertext,

    ivBase64: Buffer.from(iv).toString('base64'),

    wrappedFekBase64: Buffer.from(
      wrappedFekBuffer
    ).toString('base64'),

    wrapIvBase64: Buffer.from(
      wrapIv
    ).toString('base64'),

    fekBase64: rawFek.toString('base64'),

    masterKeyBase64: rawMasterKey.toString('base64'),
  };
}

async function decryptForTest(
  ciphertextBuffer,
  ivBase64,
  wrappedFekBase64,
  wrapIvBase64,
  masterKeyBase64
) {
  const masterKey = await subtle.importKey(
    'raw',
    Buffer.from(masterKeyBase64, 'base64'),
    {
      name: 'AES-GCM',
    },
    true,
    ['wrapKey', 'unwrapKey']
  );

  const wrappedFek = Buffer.from(
    wrappedFekBase64,
    'base64'
  );

  const wrapIv = Buffer.from(
    wrapIvBase64,
    'base64'
  );

  // Unwrap FEK using Master Key.
  const fek = await subtle.unwrapKey(
    'raw',
    wrappedFek,
    masterKey,
    {
      name: 'AES-GCM',
      iv: wrapIv,
      tagLength: 128,
    },
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );

  const iv = Buffer.from(
    ivBase64,
    'base64'
  );

  const plain = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128,
    },
    fek,
    ciphertextBuffer
  );

  return Buffer.from(plain);
}
async function uploadEncrypted(
  token,
  plainBuffer,
  {
    filename = 'secret.pdf',
    mimeType = 'application/pdf',
    overrides = {},
  } = {}
) {
  const enc = await encryptForTest(plainBuffer);

  const fields = {
    iv: enc.ivBase64,
    keyMetadata: KEY_METADATA_JSON,
    mimeType,
    originalSize: String(plainBuffer.length),

    // Required by the backend file-key hierarchy.
    wrappedFek: enc.wrappedFekBase64,
    wrapIv: enc.wrapIvBase64,

    ...overrides,
  };

  let req = request(app)
    .post('/api/files')
    .set(bearer(token));

  for (const [k, v] of Object.entries(fields)) {
    req = req.field(k, v);
  }

  const res = await req.attach(
    'file',
    enc.ciphertext,
    {
      filename,
      contentType: 'application/octet-stream',
    }
  );

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

test('data stored in S3 is ciphertext, never plaintext (verified via the SDK directly)', async () => {
  const { GetObjectCommand } = await import('@aws-sdk/client-s3');
  const { s3, BUCKET } = await import('../src/config/s3.js');

  const { token, user } = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const plaintext = Buffer.from('Sensitive S3 content check.');
  const { res: uploadRes } = await uploadEncrypted(token, plaintext, masterKey);
  const file = uploadRes.body.data.file;

  // Reads the object directly from S3 with the SDK, bypassing our own API entirely,
  // to independently confirm the bucket itself never holds plaintext.
  const s3Key = `users/${user.id}/files/${file.id}`;
  const result = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: s3Key }));
  const chunks = [];
  for await (const chunk of result.Body) chunks.push(chunk);
  const onDiskBytes = Buffer.concat(chunks);

  assert.equal(onDiskBytes.length, plaintext.length + 16); // + GCM tag
  assert.ok(!onDiskBytes.includes(plaintext), 'plaintext bytes must not appear in the S3 object');

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
test('upload: risk score and level reflect filename, type and declared sensitivity', async () => {
  const { token } = await registerAndLogin();
  const masterKey = await makeMasterKey();

  const { res } = await uploadEncrypted(token, Buffer.from('id scan bytes'), masterKey, {
    filename: 'passport_scan.pdf', mimeType: 'application/pdf',
    overrides: { userSensitivity: '3' },
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.data.file.riskLevel, 'CRITICAL');
  assert.ok(res.body.data.file.riskScore >= 9);

  await request(app).delete(`/api/files/${res.body.data.file.id}`).set(bearer(token)).expect(200);
});

test('GET /files/:id/risk returns a transparent breakdown', async () => {
  const { token } = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const { res: uploadRes } = await uploadEncrypted(token, Buffer.from('x'), masterKey, {
    filename: 'salary_slip.pdf', mimeType: 'application/pdf', overrides: { userSensitivity: '2' },
  });
  const fileId = uploadRes.body.data.file.id;

  const breakdownRes = await request(app).get(`/api/files/${fileId}/risk`).set(bearer(token));
  assert.equal(breakdownRes.status, 200);
  assert.equal(breakdownRes.body.data.fileTypeScore, 3);
  assert.ok(breakdownRes.body.data.keywordMatches.some((m) => m.pattern === 'salary'));

  await request(app).delete(`/api/files/${fileId}`).set(bearer(token)).expect(200);
});

test('risk classification is audited on upload', async () => {
  const { token, user } = await registerAndLogin();
  const masterKey = await makeMasterKey();
  const { res } = await uploadEncrypted(token, Buffer.from('x'), masterKey, { filename: 'medical_report.pdf', mimeType: 'application/pdf' });

  const logs = await query(
    "SELECT details FROM audit_logs WHERE user_id = ? AND event_type = 'RISK_CLASSIFICATION' ORDER BY id DESC LIMIT 1",
    [user.id]
  );
  assert.equal(logs.length, 1);
  assert.ok(logs[0].details.riskLevel);

  await request(app).delete(`/api/files/${res.body.data.file.id}`).set(bearer(token)).expect(200);
});

test('a forged client-side risk level is ignored: server always recomputes it', async () => {
  const { token } = await registerAndLogin();
  const masterKey = await makeMasterKey();
  // Attempt to smuggle a fake riskLevel/riskScore in the request — the route
  // has no such field in uploadRules, so this proves the server never trusts it.
  const { res } = await uploadEncrypted(token, Buffer.from('x'), masterKey, {
    filename: 'holiday.jpg', mimeType: 'image/jpeg',
    overrides: { userSensitivity: '0', riskLevel: 'LOW', riskScore: '0' },
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.data.file.riskLevel, 'LOW'); // happens to be genuinely LOW here, proving real computation, not blind trust of absent field
});