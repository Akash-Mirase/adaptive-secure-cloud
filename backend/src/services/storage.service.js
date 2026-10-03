import { GetObjectCommand, DeleteObjectCommand, HeadBucketCommand } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { s3, BUCKET } from '../config/s3.js';

// Same three function names and signatures as the Phase 6 local-disk version.
// Nothing that calls this module (controllers, tests) needed to change.
//
// `key` is always our own server-generated value: `users/{userId}/files/{fileId}`
// (built in files.controller.js). It is NEVER derived from user-supplied file
// names, so there is no path-traversal or object-key-injection risk here —
// unlike local disk, S3 has no directory traversal concept, but we still keep
// the key format restricted for consistency and auditability.

// Uses the multipart-upload-aware `Upload` helper instead of a single
// PutObjectCommand: it automatically switches to multipart upload for larger
// files and streams instead of holding one giant request buffer, which
// matters once Phase 15's performance tests push 25-50 MB files through this.
export async function putObject(key, buffer) {
  const upload = new Upload({
    client: s3,
    params: {
      Bucket: BUCKET,
      Key: key,
      Body: buffer,
      ContentType: 'application/octet-stream', // always ciphertext; the real MIME type lives only in MySQL metadata
      ServerSideEncryption: 'AES256', // SSE-S3: a second, independent at-rest layer under our own AES-256-GCM
    },
  });
  await upload.done();
}

// Returns a Node Readable stream, NOT a buffer. The Phase 6/7 version
// returned a Buffer because local disk reads are simple; over the network,
// streaming lets the controller start sending bytes to the browser before
// the whole file has even arrived from S3, and avoids holding large files
// entirely in server memory (see files.controller.js's downloadFile).
export async function getObject(key) {
  const result = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
  return { stream: result.Body, contentLength: result.ContentLength };
}

export async function deleteObject(key) {
  // S3's DeleteObject is idempotent: deleting a key that doesn't exist is not
  // an error, so unlike the local-disk version we don't need to catch ENOENT.
  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
}

// Used by the health check and at startup: confirms the bucket exists AND our
// IAM credentials can actually reach it, without reading or writing any object.
export async function checkBucketAccess() {
  await s3.send(new HeadBucketCommand({ Bucket: BUCKET }));
  return true;
}