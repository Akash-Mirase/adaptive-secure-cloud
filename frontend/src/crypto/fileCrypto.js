import { generateFileKey, generateIV, encryptFile, decryptFile, exportKey, importKey, ivToBase64, ivFromBase64, wrapFek, unwrapFek, KEY_METADATA } from './aes.js';
import { generateWrapIV } from './masterKey.js';
import { bufferToBase64, base64ToBuffer } from './encoding.js';

// File -> ciphertext + a WRAPPED FEK (under the Master Key), ready to upload.
// The raw FEK never leaves this function unwrapped.
export async function encryptFileForUpload(file, masterKey) {
  const plaintextBuffer = await file.arrayBuffer();
  const fek = await generateFileKey();
  const iv = generateIV();
  const ciphertextBuffer = await encryptFile(plaintextBuffer, fek, iv);

  const wrapIv = generateWrapIV();
  const wrappedFekBuffer = await wrapFek(fek, masterKey, wrapIv);

  return {
    ciphertextBlob: new Blob([ciphertextBuffer], { type: 'application/octet-stream' }),
    ivBase64: ivToBase64(iv),
    keyMetadata: KEY_METADATA,
    originalSize: plaintextBuffer.byteLength,
    originalMimeType: file.type || 'application/octet-stream',
    originalName: file.name,
    wrappedFekBase64: bufferToBase64(wrappedFekBuffer),
    wrapIvBase64: bufferToBase64(wrapIv),
  };
}

// Downloaded ciphertext + the wrapped FEK fetched from the server -> a Blob
// of the original file. The FEK is unwrapped in-memory and discarded after use.
export async function decryptDownloadedFile(ciphertextArrayBuffer, ivBase64, wrappedFekBase64, wrapIvBase64, masterKey, mimeType) {
  const fek = await unwrapFek(base64ToBuffer(wrappedFekBase64), masterKey, new Uint8Array(base64ToBuffer(wrapIvBase64)));
  const iv = ivFromBase64(ivBase64);
  const plaintextBuffer = await decryptFile(ciphertextArrayBuffer, fek, iv);
  return new Blob([plaintextBuffer], { type: mimeType || 'application/octet-stream' });
}

export { exportKey, importKey };