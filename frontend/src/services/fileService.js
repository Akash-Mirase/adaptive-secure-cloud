import api from './api.js';
import { encryptFileForUpload, decryptDownloadedFile, decryptSharedDownloadedFile, prepareFekForSharing } from '../crypto/fileCrypto.js';
import { importPublicKey } from '../crypto/rsa.js';
import { getMasterKey, getPrivateKey } from '../crypto/masterKeySession.js';
import { lookupUser } from './usersService.js';

function requireMasterKey() {
  const key = getMasterKey();
  if (!key) throw new Error('Your keys are locked in this tab. Please unlock and try again.');
  return key;
}

export async function uploadFile(file, { onProgress, onStageChange, userSensitivity = 0 } = {}) {
  const masterKey = requireMasterKey();
  onStageChange?.('encrypting');
  const enc = await encryptFileForUpload(file, masterKey);
  onStageChange?.('uploading');

  const formData = new FormData();
  formData.append('file', enc.ciphertextBlob, enc.originalName);
  formData.append('iv', enc.ivBase64);
  formData.append('keyMetadata', JSON.stringify(enc.keyMetadata));
  formData.append('mimeType', enc.originalMimeType);
  formData.append('originalSize', String(enc.originalSize));
  formData.append('wrappedFek', enc.wrappedFekBase64);
  formData.append('wrapIv', enc.wrapIvBase64);
  formData.append('userSensitivity', String(userSensitivity));

  const res = await api.post('/files', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (evt) => { if (evt.total) onProgress?.(Math.round((evt.loaded / evt.total) * 100)); },
  });
  return res.data.data.file;
}

export async function listFiles() {
  const res = await api.get('/files');
  return res.data.data.files;
}

export async function listSharedWithMe() {
  const res = await api.get('/files/shared-with-me');
  return res.data.data.files;
}

export async function getRiskBreakdown(id) {
  const res = await api.get(`/files/${id}/risk`);
  return res.data.data;
}

export async function getPermissions(id) {
  const res = await api.get(`/files/${id}/permissions`);
  return res.data.data.permissions;
}

// Handles BOTH cases transparently: the caller's own file (FEK wrapped under
// their Master Key) and a file shared with them (FEK wrapped under their
// RSA public key) — decided by `wrapType`, which the server returns honestly
// based on how that specific file_keys row was actually created.
export async function downloadFile(id, filename, mimeType) {
  const [{ data: meta }, { data: keyRes }] = await Promise.all([
    api.get(`/files/${id}`),
    api.get(`/files/${id}/key`),
  ]);
  const iv = meta.data.file.iv;
  const { wrappedFek, wrapIv, wrapType } = keyRes.data;

  const { data: ciphertext } = await api.get(`/files/${id}/download`, { responseType: 'arraybuffer' });

  let blob;
  if (wrapType === 'PUBLIC_KEY') {
    const privateKey = getPrivateKey();
    if (!privateKey) throw new Error('Your keys are locked in this tab. Please unlock and try again.');
    blob = await decryptSharedDownloadedFile(ciphertext, iv, wrappedFek, privateKey, mimeType);
  } else {
    const masterKey = requireMasterKey();
    blob = await decryptDownloadedFile(ciphertext, iv, wrappedFek, wrapIv, masterKey, mimeType);
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function deleteFile(id) {
  await api.delete(`/files/${id}`);
}

// Shares `fileId` with `email` at `permission`. Fetches the OWNER's own
// wrapped FEK (their Master Key unwraps it), re-wraps it under the
// recipient's public key, and sends only that ciphertext to the server.
export async function shareFile(fileId, email, permission) {
  const masterKey = requireMasterKey();
  const recipient = await lookupUser(email); // 404 surfaces as a normal error if not registered

  const { data: keyRes } = await api.get(`/files/${fileId}/key`); // may 428 for HIGH/CRITICAL — caller handles retry
  const recipientPublicKey = await importPublicKey(recipient.publicKey);
  const wrappedFekForRecipient = await prepareFekForSharing(keyRes.data.wrappedFek, keyRes.data.wrapIv, masterKey, recipientPublicKey);

  await api.post(`/files/${fileId}/share`, { email, permission, wrappedFek: wrappedFekForRecipient });
}

export async function revokeShare(fileId, userId) {
  await api.delete(`/files/${fileId}/share/${userId}`);
}