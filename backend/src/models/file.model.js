import { query } from '../config/env.js';

const toFile = (r) =>
  r && {
    id: r.id,
    ownerId: r.owner_id,
    originalName: r.original_name,
    storedName: r.stored_name,
    mimeType: r.mime_type,
    fileSize: r.file_size,
    encryptedSize: r.encrypted_size,
    s3Key: r.s3_key,
    riskScore: r.risk_score,
    riskLevel: r.risk_level,
    iv: r.iv,
    keyMetadata: r.key_metadata, // mysql2 parses JSON columns automatically
    ciphertextSha256: r.ciphertext_sha256,
    status: r.status,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };

export async function createFile(f, executor) {
  await query(
    `INSERT INTO files
       (id, owner_id, original_name, stored_name, mime_type, file_size, encrypted_size, s3_key,
        risk_score, risk_level, iv, key_metadata, ciphertext_sha256)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      f.id, f.ownerId, f.originalName, f.storedName, f.mimeType, f.fileSize, f.encryptedSize,
      f.s3Key, f.riskScore, f.riskLevel, f.iv, JSON.stringify(f.keyMetadata),
      f.ciphertextSha256 ?? null,
    ],
    executor
  );
  return f.id;
}

export async function findById(id, executor) {
  const rows = await query('SELECT * FROM files WHERE id = ?', [id], executor);
  return toFile(rows[0]) || null;
}

export async function listByOwner(ownerId, executor) {
  const rows = await query(
    "SELECT * FROM files WHERE owner_id = ? AND status = 'ACTIVE' ORDER BY created_at DESC",
    [ownerId],
    executor
  );
  return rows.map(toFile);
}

export async function markActive(id, executor) {
  await query("UPDATE files SET status = 'ACTIVE' WHERE id = ?", [id], executor);
}

export async function deleteById(id, executor) {
  const result = await query('DELETE FROM files WHERE id = ?', [id], executor);
  return result.affectedRows === 1;
}