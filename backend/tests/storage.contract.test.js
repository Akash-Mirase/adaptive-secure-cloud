import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';

process.env.NODE_ENV = 'test';
const storage = await import('../src/services/storage.service.js');

// This suite talks directly to AWS S3. Skip it if credentials aren't configured
// (e.g. a fresh clone before Phase 9's .env setup), rather than failing noisily.
const hasAwsConfig = process.env.AWS_ACCESS_KEY_ID && process.env.AWS_S3_BUCKET;

test('storage.service: bucket is reachable', { skip: !hasAwsConfig && 'AWS not configured' }, async () => {
  assert.equal(await storage.checkBucketAccess(), true);
});

test('storage.service: put, get (streamed), and delete round-trip exactly', { skip: !hasAwsConfig && 'AWS not configured' }, async () => {
  const key = `test/${randomUUID()}.bin`;
  const original = randomBytes(1024 * 50); // 50 KB, arbitrary binary content

  await storage.putObject(key, original);

  const { stream, contentLength } = await storage.getObject(key);
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  const roundTripped = Buffer.concat(chunks);

  assert.equal(contentLength, original.length);
  assert.ok(roundTripped.equals(original), 'bytes read back from S3 must exactly match what was written');

  await storage.deleteObject(key);
  await assert.rejects(async () => {
    const { stream: s2 } = await storage.getObject(key);
    for await (const _ of s2) { /* drain */ }
  }, 'object must be gone after deleteObject');
});

test('storage.service: deleting a non-existent key does not throw (idempotent)', { skip: !hasAwsConfig && 'AWS not configured' }, async () => {
  await storage.deleteObject(`test/${randomUUID()}-never-existed.bin`);
});