import { bufferToBase64, base64ToBuffer } from './encoding.js';

// The Master Key is generated ONCE per user, at registration, and never
// changes (password changes only re-wrap it under a new KEK — see recovery).
// extractable=true is required so it CAN be wrapped for storage; this does
// not weaken it, it only means our own code is permitted to export it.
export async function generateMasterKey() {
  return window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
}

export function generateWrapIV() {
  return window.crypto.getRandomValues(new Uint8Array(12));
}

// Encrypts the Master Key's raw bytes under `wrappingKey` (a KEK or a
// recovery key). The result is ciphertext — this is what is safe to store server-side.
export async function wrapMasterKey(masterKey, wrappingKey, iv) {
  const wrapped = await window.crypto.subtle.wrapKey('raw', masterKey, wrappingKey, { name: 'AES-GCM', iv, tagLength: 128 });
  return bufferToBase64(wrapped);
}

export async function unwrapMasterKey(wrappedBase64, wrappingKey, ivBase64) {
  try {
    return await window.crypto.subtle.unwrapKey(
      'raw',
      base64ToBuffer(wrappedBase64),
      wrappingKey,
      { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(ivBase64)), tagLength: 128 },
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );
  } catch {
    // Wrong password (wrong KEK) and corrupted ciphertext look identical to
    // AES-GCM by design; we don't try to distinguish them (see aes.js).
    throw new Error('Could not unlock your keys. Check your password and try again.');
  }
}