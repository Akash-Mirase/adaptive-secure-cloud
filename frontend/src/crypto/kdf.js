// PBKDF2-SHA256 turns (password, salt) into a Key Encryption Key (KEK).
// The KEK is created with usages ['wrapKey','unwrapKey'] ONLY — it is never
// exportable and its raw bytes never touch application code, reducing the
// chance a bug (or XSS) could exfiltrate it directly.
const KDF_ITERATIONS = 250000; // OWASP-range for PBKDF2-SHA256 as of 2026; tune per hardware if needed
const KEY_LENGTH_BITS = 256;

export function generateSalt() {
  return window.crypto.getRandomValues(new Uint8Array(16));
}

export const DEFAULT_KDF_ITERATIONS = KDF_ITERATIONS;

export async function deriveKek(password, saltBytes, iterations = KDF_ITERATIONS) {
  const passwordKey = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    passwordKey,
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    false, // non-extractable: the KEK's raw bytes can never be read back out
    ['wrapKey', 'unwrapKey']
  );
}