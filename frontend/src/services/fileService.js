import api from './api.js';
import { encryptFileForUpload, decryptDownloadedFile } from '../crypto/fileCrypto.js';
import { storeFileKey, getFileKey } from '../crypto/keyVault.js';

export async function uploadFile(file, { onProgress, onStageChange } = {}) {
  onStageChange?.('encrypting');
  const enc = await encryptFileForUpload(file); // happens entirely in the browser
  onStageChange?.('uploading');

  const formData = new FormData();
  formData.append('file', enc.ciphertextBlob, enc.originalName); // ciphertext only
  formData.append('iv', enc.ivBase64);
  formData.append('keyMetadata', JSON.stringify(enc.keyMetadata));
  formData.append('mimeType', enc.originalMimeType);
  formData.append('originalSize', String(enc.originalSize));

  const res = await api.post('/files', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (evt) => { if (evt.total) onProgress?.(Math.round((evt.loaded / evt.total) * 100)); },
  });

  const savedFile = res.data.data.file;
  // TEMPORARY (Phase 7): keep the FEK in this tab's memory. Phase 8 replaces
  // this with retrieving the wrapped FEK from the server and unwrapping it
  // with the user's Master Key.
  storeFileKey(savedFile.id, enc.keyBase64);
  return savedFile;
}

export async function listFiles() {
  const res = await api.get('/files');
  return res.data.data.files;
}

export async function downloadFile(id, filename, mimeType) {
  const keyBase64 = getFileKey(id);
  if (!keyBase64) {
    throw new Error(
      'The encryption key for this file is not available in this browser session. ' +
      '(Phase 7 limitation: keys are not yet persisted. Phase 8 fixes this.)'
    );
  }

  const { data: meta } = await api.get(`/files/${id}`);
  const iv = meta.data.file.iv;

  const { data: ciphertext } = await api.get(`/files/${id}/download`, { responseType: 'arraybuffer' });
  const blob = await decryptDownloadedFile(ciphertext, iv, keyBase64, mimeType); // throws on tampering / wrong key

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