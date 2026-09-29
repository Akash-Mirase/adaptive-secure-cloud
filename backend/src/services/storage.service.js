import { promises as fs } from 'node:fs';
import path from 'node:path';

// TEMPORARY implementation: files live on local disk under backend/storage/.
// Phase 9 replaces the body of these three functions with AWS S3 calls,
// keeping the exact same function names and signatures, so nothing that
// calls this module (controllers, services) has to change later.
const STORAGE_ROOT = path.resolve(process.cwd(), 'storage');

// SECURITY: build the path segment by segment and drop anything unsafe
// (e.g. "..") so a crafted key can never escape STORAGE_ROOT (path traversal).
function resolvePath(key) {
  const safeSegments = key.split('/').filter((s) => s && s !== '.' && s !== '..');
  return path.join(STORAGE_ROOT, ...safeSegments);
}

export async function putObject(key, buffer) {
  const filePath = resolvePath(key);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, buffer);
}

export async function getObject(key) {
  return fs.readFile(resolvePath(key));
}

export async function deleteObject(key) {
  try {
    await fs.unlink(resolvePath(key));
  } catch (err) {
    if (err.code !== 'ENOENT') throw err; // already gone is not an error
  }
}