import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'unit-test-secret-unit-test-secret-1234';
const { default: app } = await import('../src/app.js');
const { createAuthLimiter } = await import('../src/middleware/rateLimiters.js');

const fieldsOf = (res) => [...new Set(res.body.errors.map((e) => e.field))].sort();
const nowSec = () => Math.floor(Date.now() / 1000);

const validKeyBundle = {
  kdfIterations: 250000,
  kdfSalt: 'AAAAAAAAAAAAAAAAAAAAAA==',
  masterKeyIv: 'AAAAAAAAAAAAAAAA',
  recoveryKey: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA',
  recoveryIv: 'AAAAAAAAAAAAAAAA',
  recoveryWrappedMasterKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  wrappedMasterKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};

test('register: invalid input gets per-field errors', async () => {
  const res = await request(app)
    .post('/api/auth/register')
    .send({ name: 'A', email: 'nope', password: 'short' });
  assert.equal(res.status, 400);
  const fields = fieldsOf(res);
  assert.ok(['email', 'name', 'password'].every((f) => fields.includes(f)));
});

test('register: wrong types (objects/arrays) are rejected', async () => {
  const res = await request(app)
    .post('/api/auth/register')
    .send({ name: { $gt: '' }, email: ['a@b.com'], password: 123456789012 });
  assert.equal(res.status, 400);
});

test('register: password over 72 bytes is rejected', async () => {
  const res = await request(app)
    .post('/api/auth/register')
    .send({ name: 'Alice', email: 'alice@example.com', password: 'a'.repeat(73) });
  assert.equal(res.status, 400);
  assert.ok(fieldsOf(res).includes('password'));
});

test('login: missing fields are rejected', async () => {
  const res = await request(app).post('/api/auth/login').send({});
  assert.equal(res.status, 400);
  assert.deepEqual(fieldsOf(res), ['email', 'password']);
});

test('/me without a token returns 401', async () => {
  const res = await request(app).get('/api/auth/me');
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
});
test('a token missing the "access" purpose claim is rejected by authenticate', async () => {
  const stepUpShaped = jwt.sign({ purpose: 'step-up' }, process.env.JWT_SECRET, {
    algorithm: 'HS256', subject: '1', jwtid: 'x', issuer: 'adaptive-secure-cloud', expiresIn: '5m',
  });
  const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${stepUpShaped}`);
  assert.equal(res.status, 401);
});
test('/me with a malformed Authorization header returns 401', async () => {
  for (const header of ['Bearer', 'Basic abc', 'Bearer a b', 'garbage']) {
    const res = await request(app).get('/api/auth/me').set('Authorization', header);
    assert.equal(res.status, 401, header);
  }
});

test('token signed with the WRONG secret is rejected', async () => {
  const forged = jwt.sign({}, 'attacker-secret-attacker-secret-0000', {
    algorithm: 'HS256', subject: '1', jwtid: 'x', issuer: 'adaptive-secure-cloud', expiresIn: '5m',
  });
  const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${forged}`);
  assert.equal(res.status, 401);
});

test('unsigned token (alg: none) is rejected', async () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({
    sub: '1', jti: 'x', iss: 'adaptive-secure-cloud', exp: nowSec() + 300,
  })}.`;
  const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${unsigned}`);
  assert.equal(res.status, 401);
});

test('expired token (correct signature) is rejected', async () => {
  const expired = jwt.sign(
    { sub: '1', jti: 'x', iss: 'adaptive-secure-cloud', exp: nowSec() - 60 },
    process.env.JWT_SECRET,
    { algorithm: 'HS256' }
  );
  const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${expired}`);
  assert.equal(res.status, 401);
});

test('rate limiter blocks after the limit is reached', async () => {
  const mini = express();
  mini.post('/login', createAuthLimiter({ limit: 3 }), (req, res) => res.status(401).json({}));

  for (let i = 0; i < 3; i += 1) {
    assert.equal((await request(mini).post('/login')).status, 401);
  }
  const blocked = await request(mini).post('/login');
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.success, false);
});