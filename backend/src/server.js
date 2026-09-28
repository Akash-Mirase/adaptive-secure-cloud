import app from './app.js';
import { env, assertProductionConfig } from './config/env.js';
import { closePool } from './config/db.js';

assertProductionConfig();

const server = app.listen(env.port, () => {
  console.log(`[server] Running in ${env.nodeEnv} mode on http://localhost:${env.port}`);
});

// Stop accepting requests, then release DB connections cleanly.
process.on('SIGINT', () => {
  server.close(async () => {
    await closePool();
    process.exit(0);
  });
});