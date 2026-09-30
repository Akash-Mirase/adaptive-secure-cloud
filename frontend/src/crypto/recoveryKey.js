import { bufferToBase64, base64ToBuffer } from './encoding.js';

// A high-entropy random value (160 bits) the user must save somewhere safe
// (password manager, printed copy). It is shown ONCE, right after
// registration, and is never stored by this application in any recoverable
// form — only a bcrypt hash of it is kept server-side, purely to verify a
// future recovery attempt.
export function generateRecoveryKey() {
  const bytes = window.crypto.getRandomValues(new Uint8Array(20));
  return formatRecoveryKey(bytes);
}

// Human-friendly formatting: base64url in 4-character groups, e.g.
// "K3fA-9dQr-..." — easier to read aloud or write down than raw base64.
function formatRecoveryKey(bytes) {
  const raw = bufferToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return raw.match(/.{1,4}/g).join('-').toUpperCase();
}

function parseRecoveryKey(formatted) {
  const b64url = formatted.replace(/-/g, (m, i) => (i === formatted.lastIndexOf(m) ? m : m)); // no-op guard
  const compact = formatted.split('-').join('').toLowerCase();
  const b64 = compact.replace(/-/g, '+').replace(/_/g, '/');
  return base64ToBuffer(b64.length % 4 === 0 ? b64 : b64 + '='.repeat(4 - (b64.length % 4)));
}

// The recovery key's raw bytes ARE the wrapping key directly (it already has
// 160 bits of entropy — no KDF is needed, unlike a human-chosen password).
export async function importRecoveryWrapKey(formattedRecoveryKey) {
  const raw = parseRecoveryKey(formattedRecoveryKey);
  // AES-GCM needs a 32-byte key; we take the first 32 bytes deterministically
  // via SHA-256, so any 20-byte recovery key maps to a valid 256-bit key.
  const hash = await window.crypto.subtle.digest('SHA-256', raw);
  return window.crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);
}

// The exact string the user is asked to type back in during recovery is also
// what gets sent to the server for bcrypt verification — see authService.js.
export function normalizeRecoveryKeyInput(input) {
  return input.trim().toUpperCase();
}