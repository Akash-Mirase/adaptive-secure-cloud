import { randomUUID, createHash } from 'node:crypto';
import AppError from '../utils/AppError.js';
import { sendSuccess } from '../utils/apiResponse.js';
import * as fileModel from '../models/file.model.js';
import * as storage from '../services/storage.service.js';
import { logEvent } from '../services/audit.service.js';
import * as fileKeyModel from '../models/fileKey.model.js';
import { withTransaction } from '../config/env.js';

const GCM_TAG_BYTES = 16;

export async function uploadFile(req, res) {
  if (!req.file) throw new AppError('No file was provided (field name must be "file")', 400);

  const id = randomUUID();
  const ownerId = req.user.id;
  const buffer = req.file.buffer; // this is CIPHERTEXT: encryption already happened in the browser
  const iv = req.body.iv;
  const keyMetadata = JSON.parse(req.body.keyMetadata);
  const originalSize = req.body.originalSize;
  const mimeType = req.body.mimeType;

  // Sanity check: for AES-GCM, ciphertext length must be exactly
  // plaintext length + 16-byte auth tag. This catches corrupted uploads and
  // mismatched metadata early, independent of the cryptographic check that
  // happens later when the browser actually decrypts the file.
  const expectedSize = originalSize + GCM_TAG_BYTES;
  if (buffer.length !== expectedSize) {
    throw new AppError('Ciphertext size is inconsistent with the declared plaintext size', 400);
  }

  // A hash of what we actually stored, for detecting storage-level corruption.
  // This is NOT the security mechanism against tampering — AES-GCM's own
  // authentication tag is (verified client-side on decrypt) — this is only an
  // operational integrity check.
  const ciphertextSha256 = createHash('sha256').update(buffer).digest('hex');

  const record = {
    id,
    ownerId,
    originalName: req.file.originalname,
    storedName: id,
    mimeType,
    fileSize: originalSize,     // plaintext size, for display
    encryptedSize: buffer.length, // ciphertext size, what is actually stored
    s3Key: `users/${ownerId}/files/${id}`, // same key shape S3 will use in Phase 9
    riskScore: 0,               // placeholder until the real risk engine (Phase 10)
    riskLevel: 'LOW',           // placeholder until Phase 10
    iv,
    keyMetadata,
    ciphertextSha256,
  };

    const wrappedFek = req.body.wrappedFek;
  const wrapIv = req.body.wrapIv;

  await withTransaction(async (conn) => {
    await fileModel.createFile(record, conn);
    // The owner's own wrapped-FEK copy. Phase 12 adds one more row per
    // recipient when a file is shared — never a second copy of the plaintext key.
    await fileKeyModel.createFileKey(
      { fileId: id, userId: ownerId, wrappedFek, wrapIv, wrapType: 'MASTER_KEY' }, conn
    );
  });
  try {
    await storage.putObject(record.s3Key, buffer);
    await fileModel.markActive(id);
  } catch (err) {
    await fileModel.deleteById(id); // cascades file_keys via FK
    throw err;
  }

  await logEvent({
    userId: ownerId,
    eventType: 'UPLOAD',
    fileId: id,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: { originalName: record.originalName, size: record.fileSize, algorithm: keyMetadata.algorithm },
  });
  

  return sendSuccess(res, { file: toFileView(await fileModel.findById(id)) }, 'File uploaded', 201);
}

export async function listFiles(req, res) {
  const files = await fileModel.listByOwner(req.user.id);
  return sendSuccess(res, { files: files.map(toFileView) });
}

export async function getFile(req, res) {
  return sendSuccess(res, { file: toFileView(req.targetFile) });
}

// The backend NEVER decrypts. It serves ciphertext bytes exactly as stored;
// decryption happens only in the requesting browser.
export async function downloadFile(req, res) {
  const file = req.targetFile;
  const buffer = await storage.getObject(file.s3Key);

  await logEvent({ userId: req.user.id, eventType: 'DOWNLOAD', fileId: file.id, result: 'SUCCESS', ipAddress: req.ip });

  res.setHeader('Content-Type', 'application/octet-stream'); // honest: this is ciphertext, not the real file type
  res.setHeader('Content-Disposition', `attachment; filename="${file.id}.enc"`);
  return res.send(buffer);
}

export async function deleteFile(req, res) {
  const file = req.targetFile;
  await storage.deleteObject(file.s3Key);
  await fileModel.deleteById(file.id);
  await logEvent({ userId: req.user.id, eventType: 'DELETE', fileId: file.id, result: 'SUCCESS', ipAddress: req.ip });
  return sendSuccess(res, null, 'File deleted');
}

// Returns the CALLER's wrapped FEK for this file. Still ciphertext — the
// server does not unwrap it. Ownership/permission was already checked by
// the loadFile middleware (Phase 12 extends that check to shared recipients).
export async function getFileKey(req, res) {
  const key = await fileKeyModel.findForUser(req.targetFile.id, req.user.id);
  if (!key) throw new AppError('No key available for this file', 404);
  return sendSuccess(res, { wrappedFek: key.wrappedFek, wrapIv: key.wrapIv, wrapType: key.wrapType });
}

// The only shape of a file record that leaves the server.
// `iv` is included because the browser needs it to decrypt — an IV is not secret.
// No key material of any kind is ever part of this response.
function toFileView(f) {
  return {
    id: f.id,
    originalName: f.originalName,
    mimeType: f.mimeType,
    fileSize: f.fileSize,
    encryptedSize: f.encryptedSize,
    riskScore: f.riskScore,
    riskLevel: f.riskLevel,
    status: f.status,
    createdAt: f.createdAt,
    iv: f.iv,
    encryptionAlgorithm: f.keyMetadata?.algorithm || null,
    encryptionPending: f.keyMetadata?.algorithm !== 'AES-256-GCM',
  };
}