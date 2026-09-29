import app from './app.js';
import { env, assertProductionConfig} from './config/env.js';
import { closePool } from './config/env.js';
import { purgeExpired } from './models/revokedToken.model.js';

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

process.on('SIGINT', () => {
  clearInterval(purgeTimer);
  server.close(async () => {
    await closePool();
    process.exit(0);
  });
});