import app from './app.js';
import { env } from './config/env.js';

const server = app.listen(env.port, () => {
  console.log(`[server] Running in ${env.nodeEnv} mode on http://localhost:${env.port}`);
});

// Graceful shutdown so connections close cleanly (matters once DB pool exists).
process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});