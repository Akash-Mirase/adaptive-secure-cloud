import app from './app.js';
import { env, assertProductionConfig } from './config/env.js';

assertProductionConfig();

const server = app.listen(env.port, () => {
  console.log(`[server] Running in ${env.nodeEnv} mode on http://localhost:${env.port}`);
});

process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});