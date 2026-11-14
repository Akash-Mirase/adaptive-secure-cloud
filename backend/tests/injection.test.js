import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID , randomBytes } from 'node:crypto';
import request from 'supertest';

const b64 = (n) => randomBytes(n).toString('base64');
const PASSWORD = 'a perfectly normal password 123';

// Registers a user with the full key bundle the API now requires (Phases 8 and 12).
async function registerAndLogin(email) {
  await request(app).post('/api/auth/register').send({
    name: 'Injection Tester', email, password: PASSWORD,
    kdfSalt: b64(16), kdfIterations: 250000, wrappedMasterKey: b64(48), masterKeyIv: b64(12),
    recoveryWrappedMasterKey: b64(48), recoveryIv: b64(12), recoveryKey: 'AAAA-BBBB-CCCC-DDDD-EEEE',
    publicKey: b64(294), wrappedPrivateKey: b64(1200), privateKeyIv: b64(12),
  }).expect(201);
  const login = await request(app).post('/api/auth/login').send({ email, password: PASSWORD }).expect(200);
  return login.body.data.token;
}

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'injection-test-secret-injection-test-0000';
const { default: app } = await import('../src/app.js');
const { query, closePool } = await import('../src/config/env.js');

after(() => closePool());

const INJECTION_PAYLOADS = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  "x' UNION SELECT password_hash FROM users --",
  '<script>alert(1)</script>',
  '${7*7}',
  '{{7*7}}',
  '../../etc/passwd',
  'admin\u0000',
];


test('login: every SQL/script injection payload is treated as inert data, never breaks the query', async () => {
  for (const payload of INJECTION_PAYLOADS) {
    const res = await request(app).post('/api/auth/login').send({ email: payload, password: payload });
    // Must be a normal validation/auth failure (400 or 401), NEVER a 500
    // (a 500 here would suggest the payload broke SQL parsing or crashed the server).
    assert.ok([400, 401].includes(res.status), `payload "${payload}" caused unexpected status ${res.status}`);
  }
  // Prove the users table is still fully intact after every attempt.
  const [{ n }] = await query('SELECT COUNT(*) AS n FROM users');
  assert.ok(n >= 0); // table still queryable at all = DROP TABLE never executed
});

test('registration: an SQL-injection name is stored verbatim as inert text', async () => {
  const email = `injection-${randomUUID()}@example.com`;
  const nameInjection = "Robert'); DROP TABLE users; --";

  const res = await request(app).post('/api/auth/register').send({
    name: nameInjection, email, password: PASSWORD,
    kdfSalt: b64(16), kdfIterations: 250000, wrappedMasterKey: b64(48), masterKeyIv: b64(12),
    recoveryWrappedMasterKey: b64(48), recoveryIv: b64(12), recoveryKey: 'AAAA-BBBB-CCCC-DDDD-EEEE',
    publicKey: b64(294), wrappedPrivateKey: b64(1200), privateKeyIv: b64(12),
  });
  assert.equal(res.status, 201);

  const [row] = await query('SELECT name FROM users WHERE email = ?', [email]);
  assert.equal(row.name, nameInjection);              // stored literally, never executed
  const [{ n }] = await query('SELECT COUNT(*) AS n FROM users');
  assert.ok(n >= 1);                                  // users table still exists
  await query('DELETE FROM users WHERE email = ?', [email]);
});


test('file id parameter rejects injection attempts with 400, not a DB error', async () => {
  const email = `injection-${randomUUID()}@example.com`;
  const token = await registerAndLogin(email);

  for (const payload of INJECTION_PAYLOADS) {
    const res = await request(app).get(`/api/files/${encodeURIComponent(payload)}`).set('Authorization', `Bearer ${token}`);
    assert.equal(res.status, 400, `file id payload "${payload}" should fail UUID validation with 400`);
  }
  await query('DELETE FROM users WHERE email = ?', [email]);
});

test('audit filter query params reject injection in enum-constrained fields', async () => {
  const email = `injection-${randomUUID()}@example.com`;
  const token = await registerAndLogin(email);

  const res = await request(app).get('/api/audit/me').query({ eventType: "UPLOAD'; DROP TABLE audit_logs; --" }).set('Authorization', `Bearer ${token}`);
  assert.equal(res.status, 400); // rejected by the fixed EVENT_TYPES allow-list before ever reaching SQL

  const [{ n }] = await query('SELECT COUNT(*) AS n FROM audit_logs');
  assert.ok(n > 0, 'audit_logs must still exist and contain rows');
  await query('DELETE FROM users WHERE email = ?', [email]);
});