import dotenv from 'dotenv';

dotenv.config();

const nodeEnv = process.env.NODE_ENV || 'development';

// Single place where environment variables are read.
// SECURITY: secrets come only from the environment, never from source code.
export const env = {
  nodeEnv,
  port: Number(process.env.PORT) || 4000,
  corsOrigins: (process.env.CORS_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map((origin) => origin.trim()),

  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  },

  db: {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    name: process.env.DB_NAME || 'adaptive_secure_cloud',
  },

  aws: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
    bucket: process.env.AWS_S3_BUCKET,
  },
};

// Fail fast: refuse to boot in production with weak or missing secrets.
// A short JWT secret can be brute-forced offline, letting an attacker forge tokens.
// Called from server.js (not app.js) so tests can import the app freely.
export function assertProductionConfig() {
  if (env.nodeEnv !== 'production') return;

  const problems = [];
  if (!env.jwt.secret || env.jwt.secret.length < 32) {
    problems.push('JWT_SECRET must be set and at least 32 characters');
  }
  if (!env.db.user || !env.db.password) {
    problems.push('DB_USER and DB_PASSWORD must be set');
  }
  if (problems.length > 0) {
    throw new Error(`Invalid production configuration:\n- ${problems.join('\n- ')}`);
  }
}