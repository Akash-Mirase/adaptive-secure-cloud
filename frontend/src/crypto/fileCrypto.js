import { generateFileKey, generateIV, encryptFile, decryptFile, exportKey, importKey, ivToBase64, ivFromBase64, KEY_METADATA } from './aes.js';

// File -> ciphertext, ready to upload. One brand-new FEK per file (spec
// requirement: never reuse one key across files).
export async function encryptFileForUpload(file) {
  const plaintextBuffer = await file.arrayBuffer();
  const key = await generateFileKey();
  const iv = generateIV();
  const ciphertextBuffer = await encryptFile(plaintextBuffer, key, iv);

  return {
    ciphertextBlob: new Blob([ciphertextBuffer], { type: 'application/octet-stream' }),
    ivBase64: ivToBase64(iv),
    keyBase64: await exportKey(key),
    keyMetadata: KEY_METADATA,
    originalSize: plaintextBuffer.byteLength,
    originalMimeType: file.type || 'application/octet-stream',
    originalName: file.name,
  };
}

// Downloaded ciphertext -> a Blob of the original file, ready to save.
export async function decryptDownloadedFile(ciphertextArrayBuffer, ivBase64, keyBase64, mimeType) {
  const key = await importKey(keyBase64);
  const iv = ivFromBase64(ivBase64);
  const plaintextBuffer = await decryptFile(ciphertextArrayBuffer, key, iv);
  return new Blob([plaintextBuffer], { type: mimeType || 'application/octet-stream' });
}