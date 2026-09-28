import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';

// Must be set before the app is imported, so the request logger stays quiet.
process.env.NODE_ENV = 'test';
const { default: app } = await import('../src/app.js');

test('GET /api/health returns the standard success envelope', async () => {
  const res = await request(app).get('/api/health');
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.data.status, 'ok');
});

test('unknown route returns 404 in the standard error envelope', async () => {
  const res = await request(app).get('/api/nope');
  assert.equal(res.status, 404);
  assert.equal(res.body.success, false);
  assert.equal(res.body.data, null);
});

test('security headers are set and framework is hidden', async () => {
  const res = await request(app).get('/api/health');
  assert.equal(res.headers['x-powered-by'], undefined);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
});

test('malformed JSON returns 400 without leaking internals', async () => {
  const res = await request(app)
    .post('/api/health/validation-demo')
    .set('Content-Type', 'application/json')
    .send('{bad json');
  assert.equal(res.status, 400);
  assert.equal(res.body.message, 'Malformed JSON body');
  assert.ok(!JSON.stringify(res.body).includes('at '), 'no stack trace in response');
});

test('validation rejects invalid input with per-field errors', async () => {
  const res = await request(app)
    .post('/api/health/validation-demo')
    .send({ name: 'A', email: 'nope' });
  assert.equal(res.status, 400);
  assert.equal(res.body.message, 'Validation failed');
  assert.deepEqual(res.body.errors.map((e) => e.field).sort(), ['email', 'name']);
});

test('validation rejects wrong types (object instead of string)', async () => {
  const res = await request(app)
    .post('/api/health/validation-demo')
    .send({ name: { $gt: '' }, email: ['a@b.com'] });
  assert.equal(res.status, 400);
});

test('validation accepts good input and sanitizes it', async () => {
  const res = await request(app)
    .post('/api/health/validation-demo')
    .send({ name: '  Alice  ', email: 'ALICE@Example.COM' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.data, { name: 'Alice', email: 'alice@example.com' });
});

test('CORS: an unknown origin is not granted access', async () => {
  const res = await request(app).get('/api/health').set('Origin', 'http://evil.example');
  assert.equal(res.headers['access-control-allow-origin'], undefined);
});