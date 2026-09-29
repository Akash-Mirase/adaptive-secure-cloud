import { randomUUID, createHash } from 'node:crypto';
import AppError from '../utils/AppError.js';
import { sendSuccess } from '../utils/apiResponse.js';
import * as fileModel from '../models/file.model.js';
import * as storage from '../services/storage.service.js';
import { logEvent } from '../services/audit.service.js';

// PLACEHOLDERS, removed as real modules land:
// - IV and key metadata: meaningless until client-side AES-256-GCM (Phase 7/8)
// - risk score/level: fixed until the real risk engine (Phase 10)
const PLACEHOLDER_IV = Buffer.alloc(12).toString('base64');
const PLACEHOLDER_KEY_METADATA = {
  algorithm: 'NONE',
  version: 0,
  note: 'Placeholder. Real per-file AES-256-GCM keys are introduced in Phase 7/8.',
};

export async function uploadFile(req, res) {
  if (!req.file) throw new AppError('No file was provided (field name must be "file")', 400);

  const id = randomUUID();
  const ownerId = req.user.id;
  const buffer = req.file.buffer;
  // Integrity fingerprint of what we actually stored. Useful now for spotting
  // storage corruption; AES-GCM's own auth tag takes over as the real
  // tamper-detection mechanism from Phase 7 onward.
  const sha256 = createHash('sha256').update(buffer).digest('hex');

  const record = {
    id,
    ownerId,
    originalName: req.file.originalname,
    storedName: id,
    mimeType: req.file.mimetype,
    fileSize: buffer.length,
    encryptedSize: buffer.length, // placeholder: equals plaintext size until Phase 7 adds the GCM tag
    s3Key: `users/${ownerId}/files/${id}`, // same key shape S3 will use in Phase 9
    riskScore: 0,
    riskLevel: 'LOW',
    iv: PLACEHOLDER_IV,
    keyMetadata: PLACEHOLDER_KEY_METADATA,
    ciphertextSha256: sha256,
  };

  // Row first as PENDING, then bytes, then flip to ACTIVE. If the storage
  // write fails, the PENDING row is removed so we never point at missing bytes.
  await fileModel.createFile(record);
  try {
    await storage.putObject(record.s3Key, buffer);
    await fileModel.markActive(id);
  } catch (err) {
    await fileModel.deleteById(id);
    throw err;
  }

  await logEvent({
    userId: ownerId,
    eventType: 'UPLOAD',
    fileId: id,
    result: 'SUCCESS',
    ipAddress: req.ip,
    details: { originalName: record.originalName, size: record.fileSize },
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

export async function downloadFile(req, res) {
  const file = req.targetFile;
  const buffer = await storage.getObject(file.s3Key);

  await logEvent({ userId: req.user.id, eventType: 'DOWNLOAD', fileId: file.id, result: 'SUCCESS', ipAddress: req.ip });

  res.setHeader('Content-Type', file.mimeType);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}"`);
  return res.send(buffer);
}

export async function deleteFile(req, res) {
  const file = req.targetFile;
  await storage.deleteObject(file.s3Key);
  await fileModel.deleteById(file.id);
  await logEvent({ userId: req.user.id, eventType: 'DELETE', fileId: file.id, result: 'SUCCESS', ipAddress: req.ip });
  return sendSuccess(res, null, 'File deleted');
}

// The only shape of a file record that leaves the server.
function toFileView(f) {
  return {
    id: f.id,
    originalName: f.originalName,
    mimeType: f.mimeType,
    fileSize: f.fileSize,
    riskScore: f.riskScore,
    riskLevel: f.riskLevel,
    status: f.status,
    createdAt: f.createdAt,
    encryptionPending: f.keyMetadata?.algorithm === 'NONE',
  };
}