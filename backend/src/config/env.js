import dotenv from 'dotenv';

dotenv.config();

// Single place where environment variables are read.
// SECURITY: secrets come only from the environment, never from source code.
export const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT) || 4000,
  // Comma-separated list of allowed browser origins
  corsOrigins: (process.env.CORS_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map((origin) => origin.trim()),
};