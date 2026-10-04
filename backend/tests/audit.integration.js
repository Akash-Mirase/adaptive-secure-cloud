import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'audit-test-secret-audit-test-secret-00000000';
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/db.js');

const PASSWORD = 'correct horse battery staple';
const newEmail = () => `audittest-${randomUUID()}@example.com`;

after(async () => {
  await query("DELETE FROM users WHERE email LIKE 'audittest-%@example.com'");
  await closePool();
});

async function registerAndLogin() {
  const email = newEmail();
  await request(app).post('/api/auth/register').send({ name: 'Audit Tester', email, password: PASSWORD }).expect(201);
  const res = await request(app).post('/api/auth/login').send({ email, password: PASSWORD }).expect(200);
  return { email, token: res.body.data.token, user: res.body.data.user };
}
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

test('a normal user cannot access the admin audit list (403)', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).get('/api/audit').set(bearer(token));
  assert.equal(res.status, 403);
});

test('GET /audit/me returns only the caller\'s own events, even if userId is smuggled in the query', async () => {
  const userA = await registerAndLogin();
  const userB = await registerAndLogin();
  const res = await request(app).get('/api/audit/me').query({ userId: userB.user.id }).set(bearer(userA.token));
  assert.equal(res.status, 200);
  assert.ok(res.body.data.logs.every((l) => l.userId === userA.user.id), 'userId query param must be ignored for /audit/me');
});

test('an admin can see another user\'s events via GET /audit', async () => {
  const { token: adminToken, user: adminUser } = await registerAndLogin();
  await query("UPDATE users SET role = 'ADMIN' WHERE id = ?", [adminUser.id]);
  const other = await registerAndLogin();

  const res = await request(app).get('/api/audit').query({ userId: other.user.id }).set(bearer(adminToken));
  assert.equal(res.status, 200);
  assert.ok(res.body.data.logs.length > 0);
  assert.ok(res.body.data.logs.every((l) => l.userId === other.user.id));
});

test('filtering by eventType and result works', async () => {
  const { token } = await registerAndLogin();
  await request(app).post('/api/auth/login').send({ email: 'nobody@nowhere.example', password: 'wrong' }); // unrelated noise

  const res = await request(app).get('/api/audit/me').query({ eventType: 'REGISTER' }).set(bearer(token));
  assert.equal(res.status, 200);
  assert.ok(res.body.data.logs.every((l) => l.eventType === 'REGISTER'));
});

test('invalid eventType filter is rejected with 400', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).get('/api/audit/me').query({ eventType: 'NOT_A_REAL_EVENT' }).set(bearer(token));
  assert.equal(res.status, 400);
});

test('pagination: pageSize is respected and total reflects the full count', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).get('/api/audit/me').query({ pageSize: 1, page: 1 }).set(bearer(token));
  assert.equal(res.status, 200);
  assert.equal(res.body.data.logs.length, 1);
  assert.ok(res.body.data.total >= 1);
});

test('GET /audit/me/stats returns counts grouped by result, available to any user', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).get('/api/audit/me/stats').set(bearer(token));
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.body.data.byResult));
  assert.ok(res.body.data.byResult.some((r) => r.result === 'SUCCESS'));
});

test('a normal user cannot access the admin stats endpoint', async () => {
  const { token } = await registerAndLogin();
  const res = await request(app).get('/api/audit/stats').set(bearer(token));
  assert.equal(res.status, 403);
});

test('a failed login produces a queryable LOGIN_FAILED/FAILURE event', async () => {
  const { email, token } = await registerAndLogin();
  await request(app).post('/api/auth/login').send({ email, password: 'wrong password here' });

  const res = await request(app).get('/api/audit/me').query({ eventType: 'LOGIN_FAILED' }).set(bearer(token));
  assert.ok(res.body.data.logs.some((l) => l.result === 'FAILURE'));
});