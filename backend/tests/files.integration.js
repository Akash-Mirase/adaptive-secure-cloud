import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'files-test-secret-files-test-secret-000000';
process.env.MAX_UPLOAD_MB = '1'; // small limit just for this file's "too large" test
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/env.js');

const PASSWORD = 'correct horse battery staple';
const newEmail = () => `filetest-${randomUUID()}@example.com`;

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

test('upload requires authentication', async () => {
  const res = await request(app).post('/api/files').attach('file', Buffer.from('hi'), 'note.txt');
  assert.equal(res.status, 401);
});

test('upload, list, get metadata, download bytes match, then delete', async () => {
  const { token } = await registerAndLogin();
  const content = Buffer.from('Hello, this is a test file for Phase 6.');

  const uploadRes = await request(app)
    .post('/api/files')
    .set(bearer(token))
    .attach('file', content, { filename: 'note.txt', contentType: 'text/plain' });
  assert.equal(uploadRes.status, 201);
  const file = uploadRes.body.data.file;
  assert.equal(file.originalName, 'note.txt');
  assert.equal(file.fileSize, content.length);
  assert.equal(file.riskLevel, 'LOW');
  assert.equal(file.encryptionPending, true);
  assert.equal(file.status, 'ACTIVE');

  const listRes = await request(app).get('/api/files').set(bearer(token));
  assert.ok(listRes.body.data.files.some((f) => f.id === file.id));

  const metaRes = await request(app).get(`/api/files/${file.id}`).set(bearer(token));
  assert.equal(metaRes.status, 200);
  assert.equal(metaRes.body.data.file.id, file.id);

  const downloadRes = await request(app)
    .get(`/api/files/${file.id}/download`)
    .set(bearer(token))
    .buffer(true)
    .parse((res, cb) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => cb(null, Buffer.concat(chunks)));
    });
  assert.equal(downloadRes.status, 200);
  assert.ok(Buffer.from(downloadRes.body).equals(content), 'downloaded bytes must match the upload exactly');

  const deleteRes = await request(app).delete(`/api/files/${file.id}`).set(bearer(token));
  assert.equal(deleteRes.status, 200);

  const afterDelete = await request(app).get(`/api/files/${file.id}`).set(bearer(token));
  assert.equal(afterDelete.status, 404);
});

test("a user cannot access another user's file (404, not 403)", async () => {
  const owner = await registerAndLogin();
  const stranger = await registerAndLogin();

  const uploadRes = await request(app)
    .post('/api/files')
    .set(bearer(owner.token))
    .attach('file', Buffer.from('private'), { filename: 'secret.txt', contentType: 'text/plain' });
  const fileId = uploadRes.body.data.file.id;

  assert.equal((await request(app).get(`/api/files/${fileId}`).set(bearer(stranger.token))).status, 404);
  assert.equal((await request(app).get(`/api/files/${fileId}/download`).set(bearer(stranger.token))).status, 404);
  assert.equal((await request(app).delete(`/api/files/${fileId}`).set(bearer(stranger.token))).status, 404);

  const logs = await query(
    "SELECT COUNT(*) AS n FROM audit_logs WHERE user_id = ? AND event_type = 'ACCESS_DENIED' AND file_id = ?",
    [stranger.user.id, fileId]
  );
  assert.ok(logs[0].n >= 1, 'the denied attempt should be audited');

  await request(app).delete(`/api/files/${fileId}`).set(bearer(owner.token)).expect(200); // cleanup
});

test('invalid file id format returns 400', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).get('/api/files/not-a-uuid').set(bearer(token));
  assert.equal(res.status, 400);
});

test('disallowed file type is rejected with 415', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app)
    .post('/api/files')
    .set(bearer(token))
    .attach('file', Buffer.from('fake exe bytes'), { filename: 'virus.exe', contentType: 'application/x-msdownload' });
  assert.equal(res.status, 415);
});

test('file over the size limit is rejected with 413', async () => {
  const { token } = await registerAndLogin();
  const big = Buffer.alloc(2 * 1024 * 1024, 'a'); // 2 MB, over the 1 MB test limit
  const res = await request(app)
    .post('/api/files')
    .set(bearer(token))
    .attach('file', big, { filename: 'big.bin', contentType: 'application/octet-stream' });
  assert.equal(res.status, 413);
});

test('missing file field returns 400', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).post('/api/files').set(bearer(token)).field('note', 'no file attached');
  assert.equal(res.status, 400);
});