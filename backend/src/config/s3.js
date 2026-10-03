import { S3Client } from '@aws-sdk/client-s3';
import { env } from './env.js';

// One shared S3 client for the whole app (the SDK manages its own connection
// pool internally; there is no need to create a new client per request).
// SECURITY: credentials come ONLY from environment variables (see env.js),
// never hard-coded, matching the same rule used for the JWT secret and DB password.
export const s3 = new S3Client({
  region: env.aws.region,
  credentials: {
    accessKeyId: env.aws.accessKeyId,
    secretAccessKey: env.aws.secretAccessKey,
  },
});

export const BUCKET = env.aws.bucket;