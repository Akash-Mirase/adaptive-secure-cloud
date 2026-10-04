import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import express from 'express'
import request from 'supertest'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'integration-test-secret-integration-test-secret'
const { default: app } = await import('../src/app.js')
const { query, closePool } = await import('../src/config/env.js')
const { authenticate, requireRole } = await import('../src/middleware/auth.js')
const { errorHandler } = await import('../src/middleware/errorHandler.js')

const PASSWORD = 'correct horse battery staple'
const TEST_KEY_BUNDLE = {
  kdfIterations: 250000,
  kdfSalt: 'AAAAAAAAAAAAAAAAAAAAAA==',
  masterKeyIv: 'AAAAAAAAAAAAAAAA',
  recoveryKey: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA',
  recoveryIv: 'AAAAAAAAAAAAAAAA',
  recoveryWrappedMasterKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  wrappedMasterKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
}
const newEmail = () => `authtest-${randomUUID()}@example.com`

after(async () => {
  await query("DELETE FROM users WHERE email LIKE 'authtest-%@example.com'")
  await closePool()
})

async function registerAndLogin () {
  const email = newEmail()
  await request(app)
    .post('/api/auth/register')
    .send({
      name: 'Test User',
      email,
      password: PASSWORD,
      ...TEST_KEY_BUNDLE
    })
    .expect(201)
  const res = await request(app)
    .post('/api/auth/login')
    .send({ email, password: PASSWORD })
    .expect(200)
  return { email, token: res.body.data.token, user: res.body.data.user }
}

const bearer = token => ({ Authorization: `Bearer ${token}` })

test('register: creates the user, normalizes email, ignores injected role, leaks no secrets', async () => {
  const email = newEmail()
  const res = await request(app)
    .post('/api/auth/register')
    .send({
      name: 'Alice Test',
      email: email.toUpperCase(),
      password: PASSWORD,
      role: 'ADMIN',
      ...TEST_KEY_BUNDLE
    })
  assert.equal(res.status, 201)
  assert.equal(res.body.data.user.email, email)
  assert.equal(res.body.data.user.role, 'USER')
  const text = JSON.stringify(res.body)
  assert.ok(
    !text.includes('$2b$') &&
      !text.includes('passwordHash') &&
      !text.includes(PASSWORD)
  )
})

test('register: the stored password is a bcrypt hash, never plaintext', async () => {
  const { email } = await registerAndLogin()
  const [row] = await query('SELECT password_hash FROM users WHERE email = ?', [
    email
  ])
  assert.match(row.password_hash, /^\$2[aby]\$\d{2}\$/)
  assert.ok(!row.password_hash.includes(PASSWORD))
})

test('register: duplicate email returns 409', async () => {
  const email = newEmail()
  const body = {
    name: 'Dup',
    email,
    password: PASSWORD,
    ...TEST_KEY_BUNDLE
  }
  await request(app)
    .post('/api/auth/register')
    .send({
      name: 'Audit',
      email,
      password: PASSWORD,
      ...TEST_KEY_BUNDLE
    })
    .expect(201)
  const res = await request(app).post('/api/auth/register').send(body)
  assert.equal(res.status, 409)
})

test('step-up: wrong password is rejected, correct password issues a token', async () => {
  const { token } = await registerAndLogin()
  const wrong = await request(app)
    .post('/api/auth/step-up')
    .set(bearer(token))
    .send({ password: 'totally wrong password' })
  assert.equal(wrong.status, 401)

  const right = await request(app)
    .post('/api/auth/step-up')
    .set(bearer(token))
    .send({ password: PASSWORD })
  assert.equal(right.status, 200)
  assert.equal(right.body.data.stepUpToken.split('.').length, 3)
})

test('a step-up token cannot be used as a normal access token', async () => {
  const { token } = await registerAndLogin()
  const stepUpRes = await request(app)
    .post('/api/auth/step-up')
    .set(bearer(token))
    .send({ password: PASSWORD })
  const meRes = await request(app)
    .get('/api/auth/me')
    .set(bearer(stepUpRes.body.data.stepUpToken))
  assert.equal(meRes.status, 401)
})

test('login + /me: valid credentials give a working token', async () => {
  const { email, token } = await registerAndLogin()
  assert.equal(token.split('.').length, 3)
  const me = await request(app).get('/api/auth/me').set(bearer(token))
  assert.equal(me.status, 200)
  assert.equal(me.body.data.user.email, email)
})

test('login: wrong password and unknown email give identical errors', async () => {
  const { email } = await registerAndLogin()
  const wrongPassword = await request(app)
    .post('/api/auth/login')
    .send({ email, password: 'not the password!!' })
  const unknownEmail = await request(app)
    .post('/api/auth/login')
    .send({ email: newEmail(), password: PASSWORD })
  assert.equal(wrongPassword.status, 401)
  assert.equal(unknownEmail.status, 401)
  assert.equal(wrongPassword.body.message, unknownEmail.body.message)
})

test('logout: the token stops working immediately (revocation)', async () => {
  const { token } = await registerAndLogin()
  await request(app).get('/api/auth/me').set(bearer(token)).expect(200)
  await request(app).post('/api/auth/logout').set(bearer(token)).expect(200)
  const res = await request(app).get('/api/auth/me').set(bearer(token))
  assert.equal(res.status, 401)
})

test('lockout: 5 failures lock the account, even the correct password is refused, and it recovers', async () => {
  const { email, user } = await registerAndLogin()
  for (let i = 0; i < 5; i += 1) {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email, password: 'wrong password here' })
    assert.equal(res.status, 401)
  }
  const locked = await request(app)
    .post('/api/auth/login')
    .send({ email, password: PASSWORD })
  assert.equal(locked.status, 429)
  const [row] = await query('SELECT locked_until FROM users WHERE id = ?', [
    user.id
  ])
  assert.ok(row.locked_until, 'locked_until should be set')

  // Simulate the lock expiring, then log in normally.
  await query('UPDATE users SET locked_until = ? WHERE id = ?', [
    new Date(Date.now() - 1000),
    user.id
  ])
  await request(app)
    .post('/api/auth/login')
    .send({ email, password: PASSWORD })
    .expect(200)
  const [after] = await query(
    'SELECT failed_login_count, locked_until FROM users WHERE id = ?',
    [user.id]
  )
  assert.equal(after.failed_login_count, 0)
  assert.equal(after.locked_until, null)
})

test('a valid token for a DELETED user is rejected', async () => {
  const { token, user } = await registerAndLogin()
  await query('DELETE FROM users WHERE id = ?', [user.id])
  const res = await request(app).get('/api/auth/me').set(bearer(token))
  assert.equal(res.status, 401)
})

test('requireRole: USER gets 403 (and it is audited), ADMIN gets 200', async () => {
  const mini = express()
  mini.get('/admin-only', authenticate, requireRole('ADMIN'), (req, res) =>
    res.json({ ok: true })
  )
  mini.use(errorHandler)

  const { token, user } = await registerAndLogin()
  const denied = await request(mini).get('/admin-only').set(bearer(token))
  assert.equal(denied.status, 403)
  const logs = await query(
    "SELECT result FROM audit_logs WHERE user_id = ? AND event_type = 'ACCESS_DENIED'",
    [user.id]
  )
  assert.equal(logs.length, 1)
  assert.equal(logs[0].result, 'DENIED')

  await query("UPDATE users SET role = 'ADMIN' WHERE id = ?", [user.id])
  const allowed = await request(mini).get('/admin-only').set(bearer(token))
  assert.equal(allowed.status, 200)
})

test('audit: register, failed login and login are all recorded', async () => {
  const email = newEmail()
  await request(app)
    .post('/api/auth/register')
    .send({
      name: 'Audit',
      email,
      password: PASSWORD,
      ...TEST_KEY_BUNDLE
    })
    .expect(201)
  await request(app)
    .post('/api/auth/login')
    .send({ email, password: 'wrong password here' })
    .expect(401)
  await request(app)
    .post('/api/auth/login')
    .send({ email, password: PASSWORD })
    .expect(200)

  const [{ id }] = await query('SELECT id FROM users WHERE email = ?', [email])
  const events = (
    await query('SELECT event_type FROM audit_logs WHERE user_id = ?', [id])
  ).map(r => r.event_type)
  for (const expected of ['REGISTER', 'LOGIN_FAILED', 'LOGIN']) {
    assert.ok(events.includes(expected), `missing ${expected}`)
  }
})
