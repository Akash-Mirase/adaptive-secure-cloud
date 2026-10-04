import { generateFileKey, generateIV, encryptFile, decryptFile, exportKey, importKey, ivToBase64, ivFromBase64, wrapFek, unwrapFek, KEY_METADATA } from './aes.js';
import { generateWrapIV } from './masterKey.js';
import { wrapFekForRecipient, unwrapFekFromOwner } from './rsa.js';
import { bufferToBase64, base64ToBuffer } from './encoding.js';

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

// Owner's own download path (FEK wrapped under their Master Key).
export async function decryptDownloadedFile(ciphertextArrayBuffer, ivBase64, wrappedFekBase64, wrapIvBase64, masterKey, mimeType) {
  const fek = await unwrapFek(base64ToBuffer(wrappedFekBase64), masterKey, new Uint8Array(base64ToBuffer(wrapIvBase64)));
  const iv = ivFromBase64(ivBase64);
  const plaintextBuffer = await decryptFile(ciphertextArrayBuffer, fek, iv);
  return new Blob([plaintextBuffer], { type: mimeType || 'application/octet-stream' });
}

// Recipient's download path (FEK wrapped under the recipient's own RSA public key).
export async function decryptSharedDownloadedFile(ciphertextArrayBuffer, ivBase64, wrappedFekBase64, privateKey, mimeType) {
  const fek = await unwrapFekFromOwner(wrappedFekBase64, privateKey);
  const iv = ivFromBase64(ivBase64);
  const plaintextBuffer = await decryptFile(ciphertextArrayBuffer, fek, iv);
  return new Blob([plaintextBuffer], { type: mimeType || 'application/octet-stream' });
}

// Used only by the SHARING OWNER: unwraps their own copy of a file's FEK
// (via their Master Key) and immediately re-wraps it under a recipient's
// PUBLIC key. The raw FEK exists only transiently in this function's scope.
export async function prepareFekForSharing(wrappedFekBase64, wrapIvBase64, masterKey, recipientPublicKey) {
  const fek = await unwrapFek(base64ToBuffer(wrappedFekBase64), masterKey, new Uint8Array(base64ToBuffer(wrapIvBase64)));
  return wrapFekForRecipient(fek, recipientPublicKey);
}

export { exportKey, importKey };