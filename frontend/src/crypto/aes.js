import { bufferToBase64, base64ToBuffer } from './encoding.js';

const ALGORITHM = 'AES-GCM';
const KEY_LENGTH_BITS = 256;
// NIST SP 800-38D recommends a 96-bit (12-byte) IV for GCM: it is the most
// efficient size (no extra GHASH pass) and is what every major library uses.
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BITS = 128; // the standard, maximum-strength GCM authentication tag

// Metadata stored alongside every file so a future reader (or a different
// client implementation) knows exactly how to decrypt it. None of this is secret.
export const KEY_METADATA = {
  algorithm: 'AES-256-GCM',
  ivLength: IV_LENGTH_BYTES,
  tagLength: TAG_LENGTH_BITS,
  version: 1,
};

// Generates a brand-new random 256-bit AES-GCM key.
// extractable = true: required so the key's raw bytes can be exported to be
// wrapped under the user's Master Key in Phase 8. This does NOT weaken the key;
// it only means JavaScript is allowed to read it back out (which our own code needs).
export async function generateFileKey() {
  return window.crypto.subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH_BITS },
    true,
    ['encrypt', 'decrypt']
  );
}

// A fresh, cryptographically secure random IV for EVERY encryption operation.
// SECURITY: reusing an IV with the same key completely breaks AES-GCM — it can
// leak the plaintext XOR of two messages and allows forging valid ciphertexts.
// A new key is generated per file (see generateFileKey), and a new IV is
// generated per encryption call, so no IV is ever reused under the same key.
export function generateIV() {
  return window.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
}

// Encrypts plaintextBuffer under `key`/`iv`. Web Crypto's AES-GCM output is
// ciphertext with the 16-byte authentication tag appended automatically — there
// is nothing else to implement. Any single-bit change to the returned bytes
// will make decryption fail (see decryptFile), which is how tampering is caught.
export async function encryptFile(plaintextBuffer, key, iv) {
  return window.crypto.subtle.encrypt({ name: ALGORITHM, iv, tagLength: TAG_LENGTH_BITS }, key, plaintextBuffer);
}

export async function decryptFile(ciphertextBuffer, key, iv) {
  try {
    return await window.crypto.subtle.decrypt({ name: ALGORITHM, iv, tagLength: TAG_LENGTH_BITS }, key, ciphertextBuffer);
  } catch {
    // SubtleCrypto throws the SAME generic error whether the key is wrong or the
    // ciphertext was tampered with. We deliberately do not try to tell those
    // apart in the message: doing so would help an attacker iterate on tampering.
    throw new Error('Decryption failed: the file may be corrupted, tampered with, or the key is incorrect.');
  }
}

export async function exportKey(key) {
  return bufferToBase64(await window.crypto.subtle.exportKey('raw', key));
}

export async function importKey(base64Key) {
  return window.crypto.subtle.importKey('raw', base64ToBuffer(base64Key), { name: ALGORITHM }, true, ['encrypt', 'decrypt']);
}

export const ivToBase64 = (iv) => bufferToBase64(iv);
export const ivFromBase64 = (base64) => new Uint8Array(base64ToBuffer(base64));

// Wraps/unwraps a FEK under the Master Key. Wrapping (not just exporting +
// AES-encrypting the bytes by hand) keeps key material inside the WebCrypto
// boundary end-to-end whenever possible.
export async function wrapFek(fek, masterKey, iv) {
  return window.crypto.subtle.wrapKey('raw', fek, masterKey, { name: ALGORITHM, iv, tagLength: TAG_LENGTH_BITS });
}

export async function unwrapFek(wrappedBuffer, masterKey, iv) {
  try {
    return await window.crypto.subtle.unwrapKey(
      'raw', wrappedBuffer, masterKey,
      { name: ALGORITHM, iv, tagLength: TAG_LENGTH_BITS },
      { name: ALGORITHM, length: KEY_LENGTH_BITS },
      true,
      ['encrypt', 'decrypt']
    );
  } catch {
    throw new Error('Could not unlock this file\'s key. Your Master Key or the stored data may be invalid.');
  }
}