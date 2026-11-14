import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'keyversion-test-secret-keyversion-test-0000';
const { default: app } = await import('../src/app.js');
const { query, withTransaction, closePool } = await import('../src/config/env.js');
const userKeys = await import('../src/models/userKey.model.js');
const history = await import('../src/models/userKeyHistory.model.js');

const b64 = (n) => randomBytes(n).toString('base64');
const PASSWORD = 'correct horse battery staple';

after(async () => {
  await query("DELETE FROM users WHERE email LIKE 'keyver-%@example.com'");
  await closePool();
});

async function newUser() {
  const email = `keyver-${randomUUID()}@example.com`;
  await request(app).post('/api/auth/register').send({
    name: 'Key Version Tester', email, password: PASSWORD,
    kdfSalt: b64(16), kdfIterations: 250000, wrappedMasterKey: b64(48), masterKeyIv: b64(12),
    recoveryWrappedMasterKey: b64(48), recoveryIv: b64(12), recoveryKey: 'AAAA-BBBB-CCCC-DDDD-EEEE',
    publicKey: b64(294), wrappedPrivateKey: b64(1200), privateKeyIv: b64(12),
  }).expect(201);
  const [u] = await query('SELECT id FROM users WHERE email = ?', [email]);
  return u.id;
}
const bundle = () => ({
  wrappedMasterKey: b64(48), masterKeyIv: b64(12), recoveryWrappedMasterKey: b64(48), recoveryIv: b64(12),
  recoveryKeyHash: '$2b$04$' + 'a'.repeat(53), wrappedPrivateKey: b64(1200), privateKeyIv: b64(12),
});
const versionOf = async (id) => (await query('SELECT key_version FROM user_keys WHERE user_id = ?', [id]))[0].key_version;

test('schema: new table and column exist', async () => {
  const t = await query("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'user_key_history'");
  const c = await query("SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'file_keys' AND column_name = 'master_key_version'");
  assert.equal(t[0].n, 1);
  assert.equal(c[0].n, 1);
});

test('rotateMasterKey: correct version increments it; stale version is refused and changes nothing', async () => {
  const id = await newUser();
  assert.equal(await versionOf(id), 1);
  assert.equal(await userKeys.rotateMasterKey(id, 1, bundle()), true);
  assert.equal(await versionOf(id), 2);

  const before = (await query('SELECT wrapped_master_key FROM user_keys WHERE user_id = ?', [id]))[0].wrapped_master_key;
  assert.equal(await userKeys.rotateMasterKey(id, 1, bundle()), false); // stale: simulates a concurrent rotation
  assert.equal(await versionOf(id), 2);
  assert.equal((await query('SELECT wrapped_master_key FROM user_keys WHERE user_id = ?', [id]))[0].wrapped_master_key, before);
});

test('history: stored in version order; duplicate version is rejected', async () => {
  const id = await newUser();
  await history.insert({ userId: id, keyVersion: 2, wrappedKey: b64(48), wrapIv: b64(12) });
  await history.insert({ userId: id, keyVersion: 1, wrappedKey: b64(48), wrapIv: b64(12) });
  assert.deepEqual((await history.listForUser(id)).map((h) => h.keyVersion), [1, 2]);
  await assert.rejects(history.insert({ userId: id, keyVersion: 1, wrappedKey: b64(48), wrapIv: b64(12) }),
    (e) => e.code === 'ER_DUP_ENTRY');
});

test('interrupted rotation: a failure mid-transaction leaves version and history untouched', async () => {
  const id = await newUser();
  await assert.rejects(withTransaction(async (conn) => {
    await history.insert({ userId: id, keyVersion: 1, wrappedKey: b64(48), wrapIv: b64(12) }, conn);
    assert.equal(await userKeys.rotateMasterKey(id, 1, bundle(), conn), true);
    throw new Error('simulated crash before commit');
  }), /simulated crash/);
  assert.equal(await versionOf(id), 1);
  assert.equal((await history.listForUser(id)).length, 0);
});

test('history rows are deleted with the user (cascade)', async () => {
  const id = await newUser();
  await history.insert({ userId: id, keyVersion: 1, wrappedKey: b64(48), wrapIv: b64(12) });
  await query('DELETE FROM users WHERE id = ?', [id]);
  assert.equal((await history.listForUser(id)).length, 0);
});