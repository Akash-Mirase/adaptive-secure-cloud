import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, webcrypto } from 'node:crypto';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'sharing-test-secret-sharing-test-secret-0000';
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/db.js');

const subtle = webcrypto.subtle;
const PASSWORD = 'correct horse battery staple';
const newEmail = () => `sharetest-${randomUUID()}@example.com`;
const KEY_METADATA_JSON = JSON.stringify({ algorithm: 'AES-256-GCM', ivLength: 12, tagLength: 128, version: 1 });

after(async () => {
  await query("DELETE FROM users WHERE email LIKE 'sharetest-%@example.com'");
  await closePool();
});

// Simulates ONE full browser identity: Master Key + RSA keypair + the exact
// registration payload the real frontend would send.
async function makeBrowserUser() {
  const email = newEmail();
  const masterKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
  const masterKeyIv = webcrypto.getRandomValues(new Uint8Array(12));
  const kek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']); // stand-in for a KDF-derived KEK; its real derivation is Phase 8's concern, not this phase's
  const wrappedMasterKey = Buffer.from(await subtle.wrapKey('raw', masterKey, kek, { name: 'AES-GCM', iv: masterKeyIv, tagLength: 128 })).toString('base64');

  const keyPair = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['wrapKey', 'unwrapKey']);
  const publicKeyB64 = Buffer.from(await subtle.exportKey('spki', keyPair.publicKey)).toString('base64');
  const privateKeyIv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedPrivateKey = Buffer.from(await subtle.wrapKey('pkcs8', keyPair.privateKey, masterKey, { name: 'AES-GCM', iv: privateKeyIv, tagLength: 128 })).toString('base64');

  await request(app).post('/api/auth/register').send({
    name: 'Share Tester', email, password: PASSWORD,
    kdfSalt: randomBytes(16).toString('base64'), kdfIterations: 250000,
    wrappedMasterKey, masterKeyIv: Buffer.from(masterKeyIv).toString('base64'),
    recoveryWrappedMasterKey: randomBytes(48).toString('base64'), recoveryIv: randomBytes(12).toString('base64'),
    recoveryKey: 'AAAA-BBBB-CCCC-DDDD-EEEE',
    publicKey: publicKeyB64, wrappedPrivateKey, privateKeyIv: Buffer.from(privateKeyIv).toString('base64'),
  }).expect(201);

  const login = await request(app).post('/api/auth/login').send({ email, password: PASSWORD }).expect(200);
  return { email, token: login.body.data.token, user: login.body.data.user, masterKey, privateKey: keyPair.privateKey, publicKeyB64 };
}

const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function uploadAsOwner(owner, plaintext, { filename = 'secret.pdf', mimeType = 'application/pdf', userSensitivity = '0' } = {}) {
  const fek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, fek, plaintext));
  const wrapIv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, owner.masterKey, { name: 'AES-GCM', iv: wrapIv, tagLength: 128 })).toString('base64');

  const res = await request(app).post('/api/files').set(bearer(owner.token))
    .field('iv', Buffer.from(iv).toString('base64')).field('keyMetadata', KEY_METADATA_JSON)
    .field('mimeType', mimeType).field('originalSize', String(plaintext.length))
    .field('wrappedFek', wrappedFek).field('wrapIv', Buffer.from(wrapIv).toString('base64'))
    .field('userSensitivity', userSensitivity)
    .attach('file', ciphertext, { filename, contentType: 'application/octet-stream' });

  return { file: res.body.data.file, fek };
}

test('end-to-end share: owner shares, recipient decrypts via their OWN private key', async () => {
  const owner = await makeBrowserUser();
  const recipient = await makeBrowserUser();
  const plaintext = Buffer.from('Content only the owner and one recipient should ever read.');
  const { file, fek } = await uploadAsOwner(owner, plaintext, { filename: 'team_notes.txt', mimeType: 'text/plain' });

  // Owner wraps the SAME fek under the recipient's PUBLIC key (what ShareModal.jsx does).
  const wrappedFekForRecipient = Buffer.from(await subtle.wrapKey('raw', fek, recipient.publicKeyB64 && await subtle.importKey('spki', Buffer.from(recipient.publicKeyB64, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']), { name: 'RSA-OAEP' })).toString('base64');

  await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token))
    .send({ email: recipient.email, permission: 'DOWNLOAD', wrappedFek: wrappedFekForRecipient })
    .expect(201);

  // Recipient sees it in "shared with me".
  const sharedList = await request(app).get('/api/files/shared-with-me').set(bearer(recipient.token));
  assert.ok(sharedList.body.data.files.some((f) => f.id === file.id));

  // Recipient fetches THEIR OWN wrapped-FEK row (wrap_type = PUBLIC_KEY) and decrypts with their private key.
  const keyRes = await request(app).get(`/api/files/${file.id}/key`).set(bearer(recipient.token)).expect(200);
  assert.equal(keyRes.body.data.wrapType, 'PUBLIC_KEY');
  assert.equal(keyRes.body.data.wrapIv, null);

  const recoveredFek = await subtle.unwrapKey(
    'raw', Buffer.from(keyRes.body.data.wrappedFek, 'base64'), recipient.privateKey,
    { name: 'RSA-OAEP' }, { name: 'AES-GCM', length: 256 }, true, ['decrypt']
  );

  const downloadRes = await request(app).get(`/api/files/${file.id}/download`).set(bearer(recipient.token))
    .buffer(true).parse((res, cb) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => cb(null, Buffer.concat(chunks))); });
  const metaRes = await request(app).get(`/api/files/${file.id}`).set(bearer(recipient.token));
  const iv = Buffer.from(metaRes.body.data.file.iv, 'base64');

  const decrypted = Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, recoveredFek, Buffer.from(downloadRes.body)));
  assert.ok(decrypted.equals(plaintext), 'recipient must recover the exact original plaintext using only their own private key');

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test('a non-shared user still gets 404, not 403, on a shared file', async () => {
  const owner = await makeBrowserUser();
  const stranger = await makeBrowserUser();
  const { file } = await uploadAsOwner(owner, Buffer.from('private'), { filename: 'x.txt', mimeType: 'text/plain' });

  assert.equal((await request(app).get(`/api/files/${file.id}`).set(bearer(stranger.token))).status, 404);
  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test('VIEW permission cannot download or fetch the key (403)', async () => {
  const owner = await makeBrowserUser();
  const viewer = await makeBrowserUser();
  const { file, fek } = await uploadAsOwner(owner, Buffer.from('view only content'), { filename: 'v.txt', mimeType: 'text/plain' });

  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, await subtle.importKey('spki', Buffer.from(viewer.publicKeyB64, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']), { name: 'RSA-OAEP' })).toString('base64');
  await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token)).send({ email: viewer.email, permission: 'VIEW', wrappedFek }).expect(201);

  assert.equal((await request(app).get(`/api/files/${file.id}`).set(bearer(viewer.token))).status, 200); // metadata OK
  assert.equal((await request(app).get(`/api/files/${file.id}/download`).set(bearer(viewer.token))).status, 403);
  assert.equal((await request(app).get(`/api/files/${file.id}/key`).set(bearer(viewer.token))).status, 403);

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test('a CRITICAL file cannot be shared above VIEW, even if the client requests more', async () => {
  const owner = await makeBrowserUser();
  const recipient = await makeBrowserUser();
  const { file, fek } = await uploadAsOwner(owner, Buffer.from('id scan'), {
    filename: 'passport_scan.pdf', mimeType: 'application/pdf', userSensitivity: '3',
  });
  assert.equal(file.riskLevel, 'CRITICAL');

  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, await subtle.importKey('spki', Buffer.from(recipient.publicKeyB64, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']), { name: 'RSA-OAEP' })).toString('base64');

  const tooWide = await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token))
    .send({ email: recipient.email, permission: 'DOWNLOAD', wrappedFek });
  assert.equal(tooWide.status, 403);

  const viewOnly = await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token))
    .send({ email: recipient.email, permission: 'VIEW', wrappedFek });
  assert.equal(viewOnly.status, 201);

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test('ownership cannot be transferred via sharing', async () => {
  const owner = await makeBrowserUser();
  const recipient = await makeBrowserUser();
  const { file } = await uploadAsOwner(owner, Buffer.from('x'), { filename: 'x.txt', mimeType: 'text/plain' });

  const res = await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token))
    .send({ email: recipient.email, permission: 'OWNER', wrappedFek: Buffer.alloc(32).toString('base64') });
  assert.equal(res.status, 400);

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test('revoking access removes it: the former recipient gets 404 afterward', async () => {
  const owner = await makeBrowserUser();
  const recipient = await makeBrowserUser();
  const { file, fek } = await uploadAsOwner(owner, Buffer.from('x'), { filename: 'x.txt', mimeType: 'text/plain' });

  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, await subtle.importKey('spki', Buffer.from(recipient.publicKeyB64, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']), { name: 'RSA-OAEP' })).toString('base64');
  await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token)).send({ email: recipient.email, permission: 'DOWNLOAD', wrappedFek }).expect(201);
  assert.equal((await request(app).get(`/api/files/${file.id}`).set(bearer(recipient.token))).status, 200);

  await request(app).delete(`/api/files/${file.id}/share/${recipient.user.id}`).set(bearer(owner.token)).expect(200);
  assert.equal((await request(app).get(`/api/files/${file.id}`).set(bearer(recipient.token))).status, 404);

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test('only the owner can share, revoke, or list permissions — a recipient cannot', async () => {
  const owner = await makeBrowserUser();
  const recipient = await makeBrowserUser();
  const stranger = await makeBrowserUser();
  const { file, fek } = await uploadAsOwner(owner, Buffer.from('x'), { filename: 'x.txt', mimeType: 'text/plain' });

  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, await subtle.importKey('spki', Buffer.from(recipient.publicKeyB64, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']), { name: 'RSA-OAEP' })).toString('base64');
  await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token)).send({ email: recipient.email, permission: 'DOWNLOAD', wrappedFek }).expect(201);

  assert.equal((await request(app).get(`/api/files/${file.id}/permissions`).set(bearer(recipient.token))).status, 404);
  assert.equal((await request(app).post(`/api/files/${file.id}/share`).set(bearer(stranger.token)).send({ email: recipient.email, permission: 'VIEW', wrappedFek })).status, 404);
  assert.equal((await request(app).delete(`/api/files/${file.id}/share/${recipient.user.id}`).set(bearer(stranger.token))).status, 404);

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test('SHARE and UNSHARE are audited', async () => {
  const owner = await makeBrowserUser();
  const recipient = await makeBrowserUser();
  const { file, fek } = await uploadAsOwner(owner, Buffer.from('x'), { filename: 'x.txt', mimeType: 'text/plain' });
  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, await subtle.importKey('spki', Buffer.from(recipient.publicKeyB64, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']), { name: 'RSA-OAEP' })).toString('base64');

  await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token)).send({ email: recipient.email, permission: 'DOWNLOAD', wrappedFek }).expect(201);
  await request(app).delete(`/api/files/${file.id}/share/${recipient.user.id}`).set(bearer(owner.token)).expect(200);

  const events = (await query("SELECT event_type FROM audit_logs WHERE file_id = ? AND user_id = ?", [file.id, owner.user.id])).map((r) => r.event_type);
  assert.ok(events.includes('SHARE'));
  assert.ok(events.includes('UNSHARE'));

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});

test("re-sharing with the same recipient updates their permission instead of failing", async () => {
  const owner = await makeBrowserUser();
  const recipient = await makeBrowserUser();
  const { file, fek } = await uploadAsOwner(owner, Buffer.from('x'), { filename: 'x.txt', mimeType: 'text/plain' });
  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, await subtle.importKey('spki', Buffer.from(recipient.publicKeyB64, 'base64'), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']), { name: 'RSA-OAEP' })).toString('base64');

  await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token)).send({ email: recipient.email, permission: 'VIEW', wrappedFek }).expect(201);
  await request(app).post(`/api/files/${file.id}/share`).set(bearer(owner.token)).send({ email: recipient.email, permission: 'DOWNLOAD', wrappedFek }).expect(201);

  const perms = await request(app).get(`/api/files/${file.id}/permissions`).set(bearer(owner.token));
  const recipientRow = perms.body.data.permissions.find((p) => p.userId === recipient.user.id);
  assert.equal(recipientRow.permission, 'DOWNLOAD');

  await request(app).delete(`/api/files/${file.id}`).set(bearer(owner.token)).expect(200);
});