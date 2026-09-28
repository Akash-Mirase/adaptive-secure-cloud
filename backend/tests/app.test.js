import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { env } from '../src/config/env.js';

process.env.NODE_ENV = 'test';
const { withTransaction, query, closePool } = await import('../src/config/env.js');
const users = await import('../src/models/user.model.js');
const userKeys = await import('../src/models/userKey.model.js');
const files = await import('../src/models/file.model.js');
const fileKeys = await import('../src/models/fileKey.model.js');
const permissions = await import('../src/models/permission.model.js');
const auditLogs = await import('../src/models/auditLog.model.js');

after(() => closePool());

class Rollback extends Error {}
// Runs `fn(conn)` in a transaction and ALWAYS rolls it back afterwards.
async function inRolledBackTransaction(fn) {
  try {
    await withTransaction(async (conn) => {
      await fn(conn);
      throw new Rollback();
    });
  } catch (err) {
    if (!(err instanceof Rollback)) throw err;
  }
}

const uniqueEmail = () => `test-${randomUUID()}@example.com`;
const makeUser = (conn, email = uniqueEmail()) =>
  users.createUser({ name: 'Test User', email, passwordHash: '$2b$12$fakehashfortestingonly' }, conn);

function sampleFile(ownerId) {
  const id = randomUUID();
  return {
    id, ownerId, originalName: 'passport.pdf', storedName: id, mimeType: 'application/pdf',
    fileSize: 1_250_000, encryptedSize: 1_250_016, s3Key: `users/${ownerId}/files/${id}`,
    riskScore: 9, riskLevel: 'CRITICAL', iv: 'AAAAAAAAAAAAAAAA',
    keyMetadata: { algorithm: 'AES-256-GCM', tagBits: 128, version: 1 },
    ciphertextSha256: 'a'.repeat(64),
  };
}

test('schema: all 7 tables exist', async () => {
  const rows = await query(
    'SELECT table_name AS name FROM information_schema.tables WHERE table_schema = DATABASE()'
  );
  const names = rows.map((r) => r.name).sort();
  assert.deepEqual(names, [
    'audit_logs', 'file_keys', 'files', 'permissions', 'revoked_tokens', 'user_keys', 'users',
  ]);
});

test('models: full round trip across all tables', async () => {
  await inRolledBackTransaction(async (conn) => {
    const userId = await makeUser(conn);
    await userKeys.upsertUserKeys(userId, {
      kdfIterations: 600000, kdfSalt: 'c2FsdHNhbHRzYWx0c2E=',
      wrappedMasterKey: 'd3JhcHBlZA==', masterKeyIv: 'aXZpdml2aXZpdg==',
    }, conn);

    const file = sampleFile(userId);
    await files.createFile(file, conn);
    await fileKeys.createFileKey({
      fileId: file.id, userId, wrappedFek: 'd3JhcHBlZGZlaw==', wrapIv: 'aXZpdml2aXZpdg==', wrapType: 'MASTER_KEY',
    }, conn);
    await permissions.grant({ fileId: file.id, userId, permission: 'OWNER', grantedBy: userId }, conn);
    await auditLogs.createLog({
      userId, eventType: 'UPLOAD', fileId: file.id, ipAddress: '127.0.0.1', result: 'SUCCESS',
    }, conn);

    const stored = await files.findById(file.id, conn);
    assert.equal(stored.originalName, 'passport.pdf');
    assert.equal(stored.riskLevel, 'CRITICAL');
    assert.equal(typeof stored.fileSize, 'number');
    assert.equal(stored.keyMetadata.algorithm, 'AES-256-GCM');
    assert.equal(stored.status, 'PENDING');

    await files.markActive(file.id, conn);
    assert.equal((await files.listByOwner(userId, conn)).length, 1);
    assert.equal((await fileKeys.findForUser(file.id, userId, conn)).wrapType, 'MASTER_KEY');
    assert.equal((await permissions.find(file.id, userId, conn)).permission, 'OWNER');
    assert.equal((await userKeys.findUserKeys(userId, conn)).kdfIterations, 600000);
    assert.ok((await auditLogs.listRecent(5, conn)).length >= 1);
  });
});

test('models: deleting a user cascades to files, keys and permissions', async () => {
  await inRolledBackTransaction(async (conn) => {
    const userId = await makeUser(conn);
    const file = sampleFile(userId);
    await files.createFile(file, conn);
    await permissions.grant({ fileId: file.id, userId, permission: 'OWNER' }, conn);

    await query('DELETE FROM users WHERE id = ?', [userId], conn);
    assert.equal(await files.findById(file.id, conn), null);
    assert.equal(await permissions.find(file.id, userId, conn), null);
  });
});

test('SQL injection payload is treated as data, not SQL', async () => {
  await inRolledBackTransaction(async (conn) => {
    await makeUser(conn);
    const found = await users.findByEmail("' OR '1'='1", conn);
    assert.equal(found, null);
    const found2 = await users.findByEmail("x'; DROP TABLE users; --", conn);
    assert.equal(found2, null);
    // The table must still exist and still work:
    assert.ok((await query('SELECT COUNT(*) AS n FROM users', [], conn))[0].n >= 1);
  });
});

test('constraint: duplicate email is rejected', async () => {
  await inRolledBackTransaction(async (conn) => {
    const email = uniqueEmail();
    await makeUser(conn, email);
    await assert.rejects(makeUser(conn, email), (err) => err.code === 'ER_DUP_ENTRY');
  });
});

test('constraint: a file cannot reference a non-existent owner', async () => {
  await inRolledBackTransaction(async (conn) => {
    await assert.rejects(
      files.createFile(sampleFile(999999999), conn),
      (err) => err.code === 'ER_NO_REFERENCED_ROW_2'
    );
  });
});

test('constraint: an invalid risk level is rejected', async () => {
  await inRolledBackTransaction(async (conn) => {
    const userId = await makeUser(conn);
    await assert.rejects(files.createFile({ ...sampleFile(userId), riskLevel: 'EXTREME' }, conn));
  });
});

test('least privilege: app DB user cannot modify or delete audit logs', async () => {
  await inRolledBackTransaction(async (conn) => {
    const userId = await makeUser(conn);
    await auditLogs.createLog({ userId, eventType: 'LOGIN', result: 'SUCCESS' }, conn);
    await assert.rejects(
      query("UPDATE audit_logs SET result = 'SUCCESS'", [], conn),
      (err) => err.code === 'ER_TABLEACCESS_DENIED_ERROR'
    );
    await assert.rejects(
      query('DELETE FROM audit_logs', [], conn),
      (err) => err.code === 'ER_TABLEACCESS_DENIED_ERROR'
    );
  });
});