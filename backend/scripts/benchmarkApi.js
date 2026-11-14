// Usage: node scripts/benchmarkApi.js <label>      e.g. "before" / "after"
// Env: BENCH_EMAIL, BENCH_PASSWORD (an existing account WITHOUT MFA), BENCH_N (default 100)
import os from 'node:os';
import { writeFileSync, mkdirSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import * as fileModel from '../src/models/file.model.js';
import * as auditModel from '../src/models/auditLog.model.js';
import { query, closePool } from '../src/config/env.js';

const API = process.env.API_BASE || 'http://localhost:4000/api';
const label = process.argv[2] || 'unlabeled';
const N = Number(process.env.BENCH_N || 100);

const stats = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const pick = (p) => s[Math.min(s.length - 1, Math.floor(p * s.length))];
  return { n: s.length, minMs: s[0], p50Ms: pick(0.5), p95Ms: pick(0.95), maxMs: s[s.length - 1],
           meanMs: xs.reduce((a, b) => a + b, 0) / xs.length };
};
async function time(fn, n) {
  for (let i = 0; i < 5; i += 1) await fn(); // warm-up, discarded
  const out = [];
  for (let i = 0; i < n; i += 1) { const t = performance.now(); await fn(); out.push(performance.now() - t); }
  return stats(out);
}

const login = await fetch(`${API}/auth/login`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: process.env.BENCH_EMAIL, password: process.env.BENCH_PASSWORD }),
});
const body = await login.json();
if (!login.ok || !body.data?.token) throw new Error(`login failed: ${JSON.stringify(body)}`);
const { token, user } = body.data;
const auth = { Authorization: `Bearer ${token}` };

const endpoints = { 'GET /health': '/health', 'GET /auth/me': '/auth/me', 'GET /files': '/files', 'GET /audit/me': '/audit/me?pageSize=25' };
const api = {};
for (const [name, p] of Object.entries(endpoints)) {
  api[name] = await time(async () => { const r = await fetch(`${API}${p}`, { headers: auth }); await r.arrayBuffer(); }, N);
}
const db = {
  'files.listByOwner': await time(() => fileModel.listByOwner(user.id), N),
  'audit.listFiltered(page 1)': await time(() => auditModel.listFiltered({ userId: user.id }, { page: 1, pageSize: 25 }), N),
};
const [{ files }] = await query('SELECT COUNT(*) AS files FROM files WHERE owner_id = ?', [user.id]);
const [{ logs }] = await query('SELECT COUNT(*) AS logs FROM audit_logs');

mkdirSync('benchmark-results', { recursive: true });
const result = {
  label, takenAt: new Date().toISOString(), node: process.version, cpu: os.cpus()[0].model, cores: os.cpus().length,
  conditions: { requestsPerEndpoint: N, warmupDiscarded: 5, sequential: true, targetUserFiles: files, totalAuditRows: logs },
  api, db,
};
writeFileSync(`benchmark-results/api-${label}.json`, JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
await closePool();