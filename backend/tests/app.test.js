import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';

// Must be set before the app is imported.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'unit-test-secret-unit-test-secret-1234';
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
    .post('/api/auth/login')
    .set('Content-Type', 'application/json')
    .send('{bad json');
  assert.equal(res.status, 400);
  assert.equal(res.body.message, 'Malformed JSON body');
  assert.ok(!JSON.stringify(res.body).includes('at '), 'no stack trace in response');
});

test('CORS: an unknown origin is not granted access', async () => {
  const res = await request(app).get('/api/health').set('Origin', 'http://evil.example');
  assert.equal(res.headers['access-control-allow-origin'], undefined);
});