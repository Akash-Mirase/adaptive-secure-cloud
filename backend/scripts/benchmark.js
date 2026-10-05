import { webcrypto, randomBytes, randomUUID } from 'node:crypto';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';

const subtle = webcrypto.subtle;
const API_BASE = process.env.API_BASE || 'http://localhost:4000/api';
// Fewer repeats at larger sizes: keeps total data moved (and total run time,
// and exposure to transient network issues) reasonable, while still giving
// enough samples at small sizes — where noise matters most — to average out.
const SIZE_CONFIG = [
  { sizeMB: 1, repeats: 8 },
  { sizeMB: 5, repeats: 6 },
  { sizeMB: 10, repeats: 5 },
  { sizeMB: 25, repeats: 4 },
  { sizeMB: 50, repeats: 3 },
];
const OUT_DIR = path.resolve(process.cwd(), 'benchmark-results');
const MAX_RETRIES_PER_RUN = 2;

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });
function now() { return performance.now(); }

// Every fetch call explicitly closes its connection instead of letting
// undici's keep-alive pool reuse a socket across dozens of large transfers —
// this removes a class of "socket reset mid-transfer" failures that keep-alive
// reuse can cause under sustained, heavy, sequential load like this benchmark.
function freshFetch(url, options = {}) {
  return fetch(url, { ...options, headers: { ...(options.headers || {}), Connection: 'close' } });
}

async function registerBenchmarkUser() {
  const email = `benchmark-${randomUUID()}@example.com`;
  const password = 'benchmark testing password 123456';
  const masterKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
  const kek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
  const masterKeyIv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedMasterKey = Buffer.from(await subtle.wrapKey('raw', masterKey, kek, { name: 'AES-GCM', iv: masterKeyIv, tagLength: 128 })).toString('base64');
  const keyPair = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['wrapKey', 'unwrapKey']);
  const publicKey = Buffer.from(await subtle.exportKey('spki', keyPair.publicKey)).toString('base64');
  const privateKeyIv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedPrivateKey = Buffer.from(await subtle.wrapKey('pkcs8', keyPair.privateKey, masterKey, { name: 'AES-GCM', iv: privateKeyIv, tagLength: 128 })).toString('base64');

  const body = {
    name: 'Benchmark User', email, password,
    kdfSalt: randomBytes(16).toString('base64'), kdfIterations: 250000,
    wrappedMasterKey, masterKeyIv: Buffer.from(masterKeyIv).toString('base64'),
    recoveryWrappedMasterKey: randomBytes(48).toString('base64'), recoveryIv: randomBytes(12).toString('base64'),
    recoveryKey: 'AAAA-BBBB-CCCC-DDDD-EEEE',
    publicKey, wrappedPrivateKey, privateKeyIv: Buffer.from(privateKeyIv).toString('base64'),
  };
  const regRes = await freshFetch(`${API_BASE}/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!regRes.ok) throw new Error(`registration failed: ${regRes.status} ${await regRes.text()}`);
  const loginRes = await freshFetch(`${API_BASE}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
  const loginData = await loginRes.json();
  return { token: loginData.data.token, masterKey, email };
}

async function benchmarkOneFile(token, masterKey, sizeMB) {
  const plaintext = randomBytes(sizeMB * 1024 * 1024);
  const timings = {};

  let t0 = now();
  const fek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, fek, plaintext));
  timings.encryptionMs = now() - t0;

  t0 = now();
  const wrapIv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, masterKey, { name: 'AES-GCM', iv: wrapIv, tagLength: 128 })).toString('base64');
  timings.keyWrapMs = now() - t0;

  const formData = new FormData();
  formData.append('file', new Blob([ciphertext]), `benchmark-${sizeMB}mb.bin`);
  formData.append('iv', Buffer.from(iv).toString('base64'));
  formData.append('keyMetadata', JSON.stringify({ algorithm: 'AES-256-GCM', ivLength: 12, tagLength: 128, version: 1 }));
  formData.append('mimeType', 'application/octet-stream');
  formData.append('originalSize', String(plaintext.length));
  formData.append('wrappedFek', wrappedFek);
  formData.append('wrapIv', Buffer.from(wrapIv).toString('base64'));
  formData.append('userSensitivity', '0');

  t0 = now();
  const uploadRes = await freshFetch(`${API_BASE}/files`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: formData });
  timings.uploadMs = now() - t0;
  const uploadData = await uploadRes.json();
  if (!uploadRes.ok) throw new Error(`upload failed: ${JSON.stringify(uploadData)}`);
  const fileId = uploadData.data.file.id;

  t0 = now();
  await freshFetch(`${API_BASE}/files/${fileId}/risk`, { headers: { Authorization: `Bearer ${token}` } });
  timings.riskAnalysisMs = now() - t0;

  t0 = now();
  const downloadRes = await freshFetch(`${API_BASE}/files/${fileId}/download`, { headers: { Authorization: `Bearer ${token}` } });
  const downloadedBuffer = Buffer.from(await downloadRes.arrayBuffer());
  timings.downloadMs = now() - t0;

  t0 = now();
  const keyRes = await freshFetch(`${API_BASE}/files/${fileId}/key`, { headers: { Authorization: `Bearer ${token}` } });
  const keyData = await keyRes.json();
  const recoveredFek = await subtle.unwrapKey('raw', Buffer.from(keyData.data.wrappedFek, 'base64'), masterKey,
    { name: 'AES-GCM', iv: Buffer.from(keyData.data.wrapIv, 'base64'), tagLength: 128 },
    { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  timings.keyUnwrapMs = now() - t0;

  t0 = now();
  const decrypted = Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, recoveredFek, downloadedBuffer));
  timings.decryptionMs = now() - t0;

  if (!decrypted.equals(plaintext)) throw new Error(`INTEGRITY FAILURE at size ${sizeMB}MB: decrypted output does not match original`);

  await freshFetch(`${API_BASE}/files/${fileId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });

  timings.plaintextBytes = plaintext.length;
  timings.ciphertextBytes = ciphertext.length;
  timings.ciphertextOverheadBytes = ciphertext.length - plaintext.length;
  timings.totalProcessingMs = timings.encryptionMs + timings.keyWrapMs + timings.uploadMs + timings.downloadMs + timings.keyUnwrapMs + timings.decryptionMs;
  return timings;
}

// Wraps one run with retries: a single transient network failure (which IS
// expected occasionally when genuinely talking to AWS over the internet) is
// retried rather than aborting the entire benchmark.
async function benchmarkOneFileWithRetry(token, masterKey, sizeMB) {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES_PER_RUN + 1; attempt += 1) {
    try {
      return await benchmarkOneFile(token, masterKey, sizeMB);
    } catch (err) {
      lastErr = err;
      console.log(`    (attempt ${attempt} failed: ${err.message} — ${attempt <= MAX_RETRIES_PER_RUN ? 'retrying' : 'giving up on this run'})`);
      await new Promise((r) => setTimeout(r, 1000 * attempt)); // brief backoff
    }
  }
  throw lastErr;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

async function main() {
  console.log(`Benchmarking against ${API_BASE}`);
  console.log('Registering a throwaway benchmark user...');
  const { token, masterKey, email } = await registerBenchmarkUser();
  console.log(`Using ${email}\n`);

  const allRuns = [];
  const summary = [];

  for (const { sizeMB, repeats } of SIZE_CONFIG) {
    console.log(`--- ${sizeMB} MB (x${repeats} runs) ---`);
    const runs = [];
    for (let i = 0; i < repeats; i += 1) {
      process.stdout.write(`  run ${i + 1}/${repeats}... `);
      try {
        const result = await benchmarkOneFileWithRetry(token, masterKey, sizeMB);
        console.log(`total ${result.totalProcessingMs.toFixed(1)}ms`);
        runs.push(result);
        allRuns.push({ sizeMB, run: i + 1, ...result });
      } catch (err) {
        console.log(`SKIPPED (failed after retries: ${err.message})`);
        allRuns.push({ sizeMB, run: i + 1, error: err.message });
      }
    }

    if (runs.length === 0) {
      console.log(`  WARNING: every run at ${sizeMB}MB failed. Skipping this size in the summary.`);
      continue;
    }

    // Median, not mean: robust to the occasional real network spike without
    // needing to silently discard data as an "outlier."
    summary.push({
      sizeMB,
      successfulRuns: runs.length,
      attemptedRuns: repeats,
      medianEncryptionMs: median(runs.map((r) => r.encryptionMs)),
      medianDecryptionMs: median(runs.map((r) => r.decryptionMs)),
      medianUploadMs: median(runs.map((r) => r.uploadMs)),
      medianDownloadMs: median(runs.map((r) => r.downloadMs)),
      medianKeyWrapMs: median(runs.map((r) => r.keyWrapMs)),
      medianKeyUnwrapMs: median(runs.map((r) => r.keyUnwrapMs)),
      medianRiskAnalysisMs: median(runs.map((r) => r.riskAnalysisMs)),
      medianTotalProcessingMs: median(runs.map((r) => r.totalProcessingMs)),
      ciphertextOverheadBytes: runs[0].ciphertextOverheadBytes,
      plaintextBytes: runs[0].plaintextBytes,
    });
  }

  writeFileSync(path.join(OUT_DIR, 'raw-runs.json'), JSON.stringify(allRuns, null, 2));
  writeFileSync(path.join(OUT_DIR, 'summary.json'), JSON.stringify(summary, null, 2));

  const csvHeader = 'sizeMB,successfulRuns,attemptedRuns,medianEncryptionMs,medianDecryptionMs,medianUploadMs,medianDownloadMs,medianKeyWrapMs,medianKeyUnwrapMs,medianRiskAnalysisMs,medianTotalProcessingMs,ciphertextOverheadBytes\n';
  const csvRows = summary.map((s) =>
    [s.sizeMB, s.successfulRuns, s.attemptedRuns, s.medianEncryptionMs, s.medianDecryptionMs, s.medianUploadMs, s.medianDownloadMs, s.medianKeyWrapMs, s.medianKeyUnwrapMs, s.medianRiskAnalysisMs, s.medianTotalProcessingMs, s.ciphertextOverheadBytes]
      .map((v) => (typeof v === 'number' ? v.toFixed(2) : v)).join(',')
  ).join('\n');
  writeFileSync(path.join(OUT_DIR, 'summary.csv'), csvHeader + csvRows);

  console.log('\nDone. Results written to backend/benchmark-results/.');
}

main().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});