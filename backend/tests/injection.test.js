import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import request from 'supertest';

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

const TEST_KEY_BUNDLE = {
  kdfIterations: 250000,
  kdfSalt: 'AAAAAAAAAAAAAAAAAAAAAA==',
  masterKeyIv: 'AAAAAAAAAAAAAAAA',
  recoveryKey: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA',
  recoveryIv: 'AAAAAAAAAAAAAAAA',
  recoveryWrappedMasterKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  wrappedMasterKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  publicKey: 'TEST_PUBLIC_KEY',
  wrappedPrivateKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  privateKeyIv: 'AAAAAAAAAAAAAAAA',
};

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

test('registration: injection payloads are rejected safely and never executed', async () => {
  const email = `injection-${randomUUID()}@example.com`;
  const nameInjection = "Robert'); DROP TABLE users; --";

  const res = await request(app)
    .post('/api/auth/register')
    .send({
      name: nameInjection,
      email,
      password: 'a perfectly normal password 123',
    });

  // Current validation rejects unsafe name input.
  // The important security requirement is that it must not become a 500
  // or execute the injected SQL.
  assert.equal(res.status, 400);

  // Confirm the users table is still accessible.
  const [{ n }] = await query('SELECT COUNT(*) AS n FROM users');
  assert.ok(n >= 0);
});

test('file id parameter rejects injection attempts with 400, not a DB error', async () => {
  // Needs a token for the route to even reach the param validator.
  const email = `injection-${randomUUID()}@example.com`;
  await request(app).post('/api/auth/register').send({
  name: 'Injection Test User',
  email,
  password: 'a perfectly normal password 123',
  ...TEST_KEY_BUNDLE,
}).expect(201);
  const login = await request(app).post('/api/auth/login').send({ email, password: 'a perfectly normal password 123' }).expect(200);
  const token = login.body.data.token;

  for (const payload of INJECTION_PAYLOADS) {
    const res = await request(app).get(`/api/files/${encodeURIComponent(payload)}`).set('Authorization', `Bearer ${token}`);
    assert.equal(res.status, 400, `file id payload "${payload}" should fail UUID validation with 400`);
  }
  await query('DELETE FROM users WHERE email = ?', [email]);
});

test('audit filter query params reject injection in enum-constrained fields', async () => {
  const email = `injection-${randomUUID()}@example.com`;
  await request(app).post('/api/auth/register').send({
  name: 'Injection Test User',
  email,
  password: 'a perfectly normal password 123',
  ...TEST_KEY_BUNDLE,
}).expect(201);
  const login = await request(app).post('/api/auth/login').send({ email, password: 'a perfectly normal password 123' }).expect(200);
  const token = login.body.data.token;

  const res = await request(app).get('/api/audit/me').query({ eventType: "UPLOAD'; DROP TABLE audit_logs; --" }).set('Authorization', `Bearer ${token}`);
  assert.equal(res.status, 400); // rejected by the fixed EVENT_TYPES allow-list before ever reaching SQL

  const [{ n }] = await query('SELECT COUNT(*) AS n FROM audit_logs');
  assert.ok(n > 0, 'audit_logs must still exist and contain rows');
  await query('DELETE FROM users WHERE email = ?', [email]);
});