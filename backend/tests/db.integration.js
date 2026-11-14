import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

process.env.NODE_ENV = 'test';
const { query, closePool } = await import('../src/config/env.js');
const users = await import('../src/models/user.model.js');

after(() => closePool());

test('schema: all required tables exist', async () => {
  const rows = await query('SELECT table_name AS name FROM information_schema.tables WHERE table_schema = DATABASE()');
  const names = rows.map((r) => r.name);
  for (const t of ['users', 'user_keys', 'files', 'file_keys', 'permissions', 'audit_logs',
    'revoked_tokens', 'user_mfa', 'mfa_recovery_codes', 'user_key_history', 'security_alerts']) {
    assert.ok(names.includes(t), `missing table ${t}`);
  }
});

test('SQL injection payload is treated as data, not SQL', async () => {
  assert.equal(await users.findByEmail("' OR '1'='1"), null);
  assert.equal(await users.findByEmail("x'; DROP TABLE users; --"), null);
  const [{ n }] = await query('SELECT COUNT(*) AS n FROM users');
  assert.ok(n >= 0);
});

test('constraint: duplicate email is rejected', async () => {
  const email = `dbtest-${randomUUID()}@example.com`;
  await users.createUser({ name: 'DB Test', email, passwordHash: '$2b$04$fakehashfortestingonly' });
  await assert.rejects(
    users.createUser({ name: 'DB Test', email, passwordHash: '$2b$04$fakehashfortestingonly' }),
    (e) => e.code === 'ER_DUP_ENTRY');
  await query('DELETE FROM users WHERE email = ?', [email]);
});

test('least privilege: app DB user cannot modify or delete audit logs', async () => {
  await assert.rejects(query("UPDATE audit_logs SET result = 'SUCCESS' WHERE id = -1"),
    (e) => e.code === 'ER_TABLEACCESS_DENIED_ERROR');
  await assert.rejects(query('DELETE FROM audit_logs WHERE id = -1'),
    (e) => e.code === 'ER_TABLEACCESS_DENIED_ERROR');
});