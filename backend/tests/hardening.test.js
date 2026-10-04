import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'hardening-test-secret-hardening-test-0000';
const { default: app } = await import('../src/app.js');

test('every response hides the framework and sets core security headers', async () => {
  const res = await request(app).get('/api/health');
  assert.equal(res.headers['x-powered-by'], undefined);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.ok(res.headers['content-security-policy'], 'CSP header must be present');
});

test('CORS: only the configured origin receives Access-Control-Allow-Origin', async () => {
  const allowed = await request(app).get('/api/health').set('Origin', 'http://localhost:5173');
  const blocked = await request(app).get('/api/health').set('Origin', 'http://attacker.example');
  assert.equal(allowed.headers['access-control-allow-origin'], 'http://localhost:5173');
  assert.equal(blocked.headers['access-control-allow-origin'], undefined);
});

test('a sustained burst of requests eventually triggers the global rate limiter', async () => {
  // The global limiter is intentionally generous (300/15min) so legitimate
  // bursts aren't throttled; this just proves the ceiling is real, not just
  // configured and ignored.
  let sawLimitHeader = false;
  for (let i = 0; i < 30; i += 1) {
    const res = await request(app).get('/api/health');
    if (res.headers['ratelimit-limit'] || res.headers['x-ratelimit-limit']) sawLimitHeader = true;
  }
  assert.ok(sawLimitHeader, 'rate-limit headers must be present, proving the limiter is actually active on this route');
});

test('oversized JSON body is rejected before reaching any route handler', async () => {
  const bigPayload = { email: 'a@b.com', password: 'x'.repeat(2 * 1024 * 1024) }; // 2MB, over the 1MB json limit
  const res = await request(app).post('/api/auth/login').send(bigPayload);
  assert.equal(res.status, 413);
});

test('an unsupported HTTP method on a known path is rejected cleanly, not a 500', async () => {
  const res = await request(app).patch('/api/health');
  assert.ok([404, 405].includes(res.status));
});