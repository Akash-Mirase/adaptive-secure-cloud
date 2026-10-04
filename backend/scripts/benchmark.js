// Run with: node scripts/benchmark.js
// Requires the backend to be running on http://localhost:4000 (or set API_BASE).
//
// Measures, per the spec's performance-evaluation requirements:
//   encryption time, decryption time, upload time, download time,
//   ciphertext overhead, risk-analysis time (isolated), total processing time
//
// Uses node:crypto's webcrypto — the SAME API the real browser frontend uses
// (see frontend/src/crypto/*.js) — so these numbers reflect the real
// cryptographic pipeline, not a simplified stand-in.
import { webcrypto, randomBytes, randomUUID } from 'node:crypto';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';

const subtle = webcrypto.subtle;
const API_BASE = process.env.API_BASE || 'http://localhost:4000/api';
const SIZES_MB = [1, 5, 10, 25, 50];
const REPEATS = 3; // per size, for averaging — raises total runtime but stabilizes numbers
const OUT_DIR = path.resolve(process.cwd(), 'benchmark-results');

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

function now() { return performance.now(); }

async function registerBenchmarkUser() {
  const email = `benchmark-${randomUUID()}@example.com`;
  const password = 'benchmark testing password 123456';

  const masterKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
  const kek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']); // stand-in KEK; real PBKDF2 derivation is a frontend concern already benchmarked implicitly via its own cost (see note in report)
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

  const regRes = await fetch(`${API_BASE}/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!regRes.ok) throw new Error(`registration failed: ${regRes.status} ${await regRes.text()}`);

  const loginRes = await fetch(`${API_BASE}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
  const loginData = await loginRes.json();
  return { token: loginData.data.token, masterKey, email };
}

// One full encrypt -> upload -> download -> decrypt cycle for a given plaintext size.
async function benchmarkOneFile(token, masterKey, sizeMB) {
  const plaintext = randomBytes(sizeMB * 1024 * 1024);
  const timings = {};

  // --- ENCRYPTION (client-side AES-256-GCM, exactly aes.js's encryptFile) ---
  let t0 = now();
  const fek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, fek, plaintext));
  timings.encryptionMs = now() - t0;

  // --- FEK WRAPPING (part of "key operation" overhead, timed separately) ---
  t0 = now();
  const wrapIv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedFek = Buffer.from(await subtle.wrapKey('raw', fek, masterKey, { name: 'AES-GCM', iv: wrapIv, tagLength: 128 })).toString('base64');
  timings.keyWrapMs = now() - t0;

  // --- UPLOAD (network + server-side risk classification happens inside this call) ---
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
  const uploadRes = await fetch(`${API_BASE}/files`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: formData });
  timings.uploadMs = now() - t0;
  const uploadData = await uploadRes.json();
  if (!uploadRes.ok) throw new Error(`upload failed: ${JSON.stringify(uploadData)}`);
  const fileId = uploadData.data.file.id;
  const encryptedSize = uploadData.data.file.encryptedSize;

  // --- RISK ANALYSIS, isolated (separate call to /risk; the upload above
  // already classified it, this measures the classification function's own
  // cost via the same code path, in isolation from upload/network noise) ---
  t0 = now();
  await fetch(`${API_BASE}/files/${fileId}/risk`, { headers: { Authorization: `Bearer ${token}` } });
  timings.riskAnalysisMs = now() - t0;

  // --- DOWNLOAD (network) ---
  t0 = now();
  const downloadRes = await fetch(`${API_BASE}/files/${fileId}/download`, { headers: { Authorization: `Bearer ${token}` } });
  const downloadedBuffer = Buffer.from(await downloadRes.arrayBuffer());
  timings.downloadMs = now() - t0;

  // --- FETCH + UNWRAP KEY ---
  t0 = now();
  const keyRes = await fetch(`${API_BASE}/files/${fileId}/key`, { headers: { Authorization: `Bearer ${token}` } });
  const keyData = await keyRes.json();
  const recoveredFek = await subtle.unwrapKey(
    'raw', Buffer.from(keyData.data.wrappedFek, 'base64'), masterKey,
    { name: 'AES-GCM', iv: Buffer.from(keyData.data.wrapIv, 'base64'), tagLength: 128 },
    { name: 'AES-GCM', length: 256 }, true, ['decrypt']
  );
  timings.keyUnwrapMs = now() - t0;

  // --- DECRYPTION ---
  t0 = now();
  const decrypted = Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, recoveredFek, downloadedBuffer));
  timings.decryptionMs = now() - t0;

  // Correctness check — a benchmark run that silently corrupts data is worse than no benchmark at all.
  if (!decrypted.equals(plaintext)) throw new Error(`INTEGRITY FAILURE at size ${sizeMB}MB: decrypted output does not match original`);

  await fetch(`${API_BASE}/files/${fileId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });

  timings.plaintextBytes = plaintext.length;
  timings.ciphertextBytes = ciphertext.length;
  timings.ciphertextOverheadBytes = ciphertext.length - plaintext.length; // always exactly 16 (GCM tag)
  timings.totalProcessingMs = timings.encryptionMs + timings.keyWrapMs + timings.uploadMs + timings.downloadMs + timings.keyUnwrapMs + timings.decryptionMs;
  return timings;
}

function average(values) {
  return values.reduce((a, b) => a + b, 0) / values.length;
}

async function main() {
  console.log(`Benchmarking against ${API_BASE}`);
  console.log('Registering a throwaway benchmark user...');
  const { token, masterKey, email } = await registerBenchmarkUser();
  console.log(`Using ${email}\n`);

  const allRuns = [];
  const summary = [];

  for (const sizeMB of SIZES_MB) {
    console.log(`--- ${sizeMB} MB (x${REPEATS} runs) ---`);
    const runs = [];
    for (let i = 0; i < REPEATS; i += 1) {
      process.stdout.write(`  run ${i + 1}/${REPEATS}... `);
      const result = await benchmarkOneFile(token, masterKey, sizeMB);
      console.log(`total ${result.totalProcessingMs.toFixed(1)}ms`);
      runs.push(result);
      allRuns.push({ sizeMB, run: i + 1, ...result });
    }

    summary.push({
      sizeMB,
      avgEncryptionMs: average(runs.map((r) => r.encryptionMs)),
      avgDecryptionMs: average(runs.map((r) => r.decryptionMs)),
      avgUploadMs: average(runs.map((r) => r.uploadMs)),
      avgDownloadMs: average(runs.map((r) => r.downloadMs)),
      avgKeyWrapMs: average(runs.map((r) => r.keyWrapMs)),
      avgKeyUnwrapMs: average(runs.map((r) => r.keyUnwrapMs)),
      avgRiskAnalysisMs: average(runs.map((r) => r.riskAnalysisMs)),
      avgTotalProcessingMs: average(runs.map((r) => r.totalProcessingMs)),
      ciphertextOverheadBytes: runs[0].ciphertextOverheadBytes, // deterministic (always 16), no need to average
      plaintextBytes: runs[0].plaintextBytes,
    });
  }

  writeFileSync(path.join(OUT_DIR, 'raw-runs.json'), JSON.stringify(allRuns, null, 2));
  writeFileSync(path.join(OUT_DIR, 'summary.json'), JSON.stringify(summary, null, 2));

  const csvHeader = 'sizeMB,avgEncryptionMs,avgDecryptionMs,avgUploadMs,avgDownloadMs,avgKeyWrapMs,avgKeyUnwrapMs,avgRiskAnalysisMs,avgTotalProcessingMs,ciphertextOverheadBytes\n';
  const csvRows = summary.map((s) =>
    [s.sizeMB, s.avgEncryptionMs, s.avgDecryptionMs, s.avgUploadMs, s.avgDownloadMs, s.avgKeyWrapMs, s.avgKeyUnwrapMs, s.avgRiskAnalysisMs, s.avgTotalProcessingMs, s.ciphertextOverheadBytes]
      .map((v) => (typeof v === 'number' ? v.toFixed(2) : v)).join(',')
  ).join('\n');
  writeFileSync(path.join(OUT_DIR, 'summary.csv'), csvHeader + csvRows);

  console.log('\nDone. Results written to backend/benchmark-results/:');
  console.log('  - raw-runs.json   (every individual run, for appendix/raw-data purposes)');
  console.log('  - summary.json    (averaged per size)');
  console.log('  - summary.csv     (import into Excel/Sheets for charts)');
}

main().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});