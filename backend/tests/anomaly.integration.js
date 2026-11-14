import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'anomaly-test-secret-anomaly-test-0000000';
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/env.js');
const auditLogs = await import('../src/models/auditLog.model.js');
const alerts = await import('../src/models/securityAlert.model.js');
const { evaluateUser } = await import('../src/services/anomaly.service.js');

const b64 = (n) => randomBytes(n).toString('base64');
after(async () => { await query("DELETE FROM users WHERE email LIKE 'anomaly-%@example.com'"); await closePool(); });

async function newUser() {
  const email = `anomaly-${randomUUID()}@example.com`;
  await request(app).post('/api/auth/register').send({
    name: 'Anomaly Tester', email, password: 'correct horse battery staple',
    kdfSalt: b64(16), kdfIterations: 250000, wrappedMasterKey: b64(48), masterKeyIv: b64(12),
    recoveryWrappedMasterKey: b64(48), recoveryIv: b64(12), recoveryKey: 'AAAA-BBBB-CCCC-DDDD-EEEE',
    publicKey: b64(294), wrappedPrivateKey: b64(1200), privateKeyIv: b64(12),
  }).expect(201);
  return (await query('SELECT id FROM users WHERE email = ?', [email]))[0].id;
}
const seed = async (userId, eventType, result, n) => {
  for (let i = 0; i < n; i += 1) await auditLogs.createLog({ userId, eventType, result });
};

test('normal behavior raises no alert', async () => {
  const id = await newUser();
  await seed(id, 'LOGIN_FAILED', 'FAILURE', 2);
  await seed(id, 'DOWNLOAD', 'SUCCESS', 5);
  assert.deepEqual(await evaluateUser(id), []);
});

test('repeated failed logins raise an explainable MEDIUM alert with no restriction', async () => {
  const id = await newUser();
  await seed(id, 'LOGIN_FAILED', 'FAILURE', 5);
  const raised = await evaluateUser(id);
  assert.equal(raised.length, 1);
  assert.equal(raised[0].rule, 'FAILED_LOGINS');
  assert.equal(raised[0].severity, 'MEDIUM');
  assert.match(raised[0].message, /5 failed login attempts/);
  assert.equal(raised[0].restriction, 'NONE');
});

test('repeated unauthorized access requires step-up temporarily', async () => {
  const id = await newUser();
  await seed(id, 'ACCESS_DENIED', 'DENIED', 5);
  const [a] = await evaluateUser(id);
  assert.equal(a.restriction, 'REQUIRE_STEP_UP');
  assert.ok(a.expiresAt > new Date(), 'restriction must have a future expiry');
  assert.equal(await alerts.hasActiveRestriction(id, 'REQUIRE_STEP_UP'), true);
});

test('bulk downloads throttle downloads', async () => {
  const id = await newUser();
  await seed(id, 'DOWNLOAD', 'SUCCESS', 20);
  const [a] = await evaluateUser(id);
  assert.equal(a.rule, 'BULK_DOWNLOADS');
  assert.equal(await alerts.hasActiveRestriction(id, 'THROTTLE_DOWNLOADS'), true);
});

test('abnormal sharing raises an alert', async () => {
  const id = await newUser();
  await seed(id, 'SHARE', 'SUCCESS', 10);
  assert.equal((await evaluateUser(id))[0].rule, 'SHARING_BURST');
});

test('the same burst is not alerted twice (dedupe)', async () => {
  const id = await newUser();
  await seed(id, 'ACCESS_DENIED', 'DENIED', 6);
  assert.equal((await evaluateUser(id)).length, 1);
  assert.equal((await evaluateUser(id)).length, 0);
});

test('restrictions expire: never a permanent lockout from a false positive', async () => {
  const id = await newUser();

  // An alert whose restriction expired a second ago must not count as active.
  await alerts.create({
    userId: id, rule: 'BULK_DOWNLOADS', severity: 'HIGH', message: 'expired restriction',
    details: null, restriction: 'THROTTLE_DOWNLOADS', expiresAt: new Date(Date.now() - 1000),
  });
  assert.equal(await alerts.hasActiveRestriction(id, 'THROTTLE_DOWNLOADS'), false);

  // An alert with a future expiry must count as active.
  await alerts.create({
    userId: id, rule: 'BULK_DOWNLOADS', severity: 'HIGH', message: 'active restriction',
    details: null, restriction: 'THROTTLE_DOWNLOADS', expiresAt: new Date(Date.now() + 60000),
  });
  assert.equal(await alerts.hasActiveRestriction(id, 'THROTTLE_DOWNLOADS'), true);
});

test('alerts API: users see only their own; admin list is admin-only', async () => {
  const id = await newUser();
  await seed(id, 'LOGIN_FAILED', 'FAILURE', 5);
  await evaluateUser(id);
  const email = (await query('SELECT email FROM users WHERE id = ?', [id]))[0].email;
  const login = await request(app).post('/api/auth/login').send({ email, password: 'correct horse battery staple' }).expect(200);
  const t = { Authorization: `Bearer ${login.body.data.token}` };
  const mine = await request(app).get('/api/alerts/me').set(t).expect(200);
  assert.ok(mine.body.data.alerts.every((a) => a.userId === id));
  assert.equal((await request(app).get('/api/alerts').set(t)).status, 403);
});