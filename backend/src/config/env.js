import dotenv from 'dotenv'
import mysql from 'mysql2/promise'

dotenv.config()

const nodeEnv = process.env.NODE_ENV || 'development'

// Single place where environment variables are read.
// SECURITY: secrets come only from the environment, never from source code.
export const env = {
  nodeEnv,
  port: Number(process.env.PORT) || 4000,
  maxUploadMb: Number(process.env.MAX_UPLOAD_MB) || 100,
  corsOrigins: (process.env.CORS_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map(origin => origin.trim()),

  bcryptRounds: nodeEnv === 'test' ? 4 : 12,

  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '15m'
  },

  db: {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    name: process.env.DB_NAME || 'adaptive_secure_cloud'
  },

  aws: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
    bucket: process.env.AWS_S3_BUCKET
  }
}

// Fail fast: refuse to boot in production with weak or missing secrets.
// A short JWT secret can be brute-forced offline, letting an attacker forge tokens.
// Called from server.js (not app.js) so tests can import the app freely.
export function assertProductionConfig () {
  const problems = []
  if (!env.jwt.secret || env.jwt.secret.length < 32) {
    problems.push('JWT_SECRET must be set and at least 32 characters')
  }
  if (env.nodeEnv !== 'test') {
    if (
      !env.aws.accessKeyId ||
      !env.aws.secretAccessKey ||
      !env.aws.region ||
      !env.aws.bucket
    ) {
      problems.push(
        'AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION and AWS_S3_BUCKET must all be set'
      )
    }
  }
  if (env.nodeEnv === 'production' && (!env.db.user || !env.db.password)) {
    problems.push('DB_USER and DB_PASSWORD must be set')
  }
  if (problems.length > 0) {
    throw new Error(
      `Invalid production configuration:\n- ${problems.join('\n- ')}`
    )
  }
}

// Connection pool: reuses connections instead of opening one per request.
// SECURITY: multipleStatements stays false (the default), so an injected
// "; DROP TABLE ..." cannot run as a second statement.
export const pool = mysql.createPool({
  host: env.db.host,
  port: env.db.port,
  user: env.db.user,
  password: env.db.password,
  database: env.db.name,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4',
  timezone: 'Z', // store and read UTC
  supportBigNumbers: true, // BIGINT (file sizes) returned as Number when safe
  bigNumberStrings: false,
  multipleStatements: false
})

// mysql2 throws on `undefined` parameters; convert to SQL NULL.
const normalize = params => params.map(p => (p === undefined ? null : p))

// Every query goes through here.
// SECURITY: pool.execute() sends the SQL and the values SEPARATELY (prepared
// statement), so user input can never change the structure of the query.
// This is what prevents SQL injection. NEVER build SQL by string concatenation.
// `executor` is the pool by default, or a transaction connection.
export async function query (sql, params = [], executor = pool) {
  const [rows] = await executor.execute(sql, normalize(params))
  return rows
}

// Runs `work(conn)` atomically: all statements succeed, or none are applied.
// Needed later so "create file + wrapped key + permission" is all-or-nothing.
export async function withTransaction (work) {
  const conn = await pool.getConnection()
  try {
    await conn.beginTransaction()
    const result = await work(conn)
    await conn.commit()
    return result
  } catch (err) {
    await conn.rollback()
    throw err
  } finally {
    conn.release()
  }
}

export async function pingDatabase () {
  await query('SELECT 1 AS ok')
  return true
}

export async function closePool () {
  await pool.end()
}
