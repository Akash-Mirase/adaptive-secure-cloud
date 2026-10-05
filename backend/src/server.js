import app from './app.js';
import { env, assertProductionConfig} from './config/env.js';
import { closePool } from './config/env.js';
import { purgeExpired } from './models/revokedToken.model.js';
import { checkBucketAccess } from './services/storage.service.js';

if (env.nodeEnv !== 'test') {
  checkBucketAccess()
    .then(() => console.log(`[s3] Bucket "${env.aws.bucket}" is reachable`))
    .catch((err) => console.error(`[s3] WARNING: cannot reach bucket "${env.aws.bucket}": ${err.name} — ${err.message}`));
}
assertProductionConfig ();

// Housekeeping: drop revocation entries whose tokens have expired anyway.
async function purgeRevokedTokens() {
  try {
    const removed = await purgeExpired();
    if (removed > 0) console.log(`[auth] purged ${removed} expired revoked token(s)`);
  } catch (err) {
    console.error('[auth] purge failed:', err.code || err.message);
  }
}
purgeRevokedTokens();
const purgeTimer = setInterval(purgeRevokedTokens, 60 * 60 * 1000);
purgeTimer.unref(); // never keep the process alive just for this timer

const server = app.listen(env.port, () => {
  console.log(`[server] Running in ${env.nodeEnv} mode on http://localhost:${env.port}`);
});

// Default Node keep-alive timeout (5s) can prematurely close a reused
// connection between the benchmark script's back-to-back large transfers.
// This is relevant for sustained load (like this benchmark); normal browser
// usage is unaffected.
server.keepAliveTimeout = 120000;
server.headersTimeout = 125000; // must exceed keepAliveTimeout

process.on('SIGINT', () => {
  clearInterval(purgeTimer);
  server.close(async () => {
    await closePool();
    process.exit(0);
  });
});