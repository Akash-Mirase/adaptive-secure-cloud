// TEMPORARY — replaced in Phase 8.
//
// Holds each file's raw File Encryption Key (FEK) in memory, in THIS browser
// tab only, so the full upload -> download -> decrypt pipeline can be proven
// correct before Phase 8 adds real key management (the FEK wrapped under the
// user's password-derived Master Key, persisted server-side in `file_keys`,
// and unwrapped only inside the browser).
//
// The key never leaves this module except to be handed to the AES functions.
// It is NEVER sent to the backend and NEVER written to sessionStorage,
// localStorage, or any disk. A page reload or a new tab therefore loses the
// ability to decrypt previously uploaded files — that is expected here and is
// exactly what Phase 8 fixes.
const vault = new Map();

export function storeFileKey(fileId, keyBase64) {
  vault.set(fileId, keyBase64);
}
export function getFileKey(fileId) {
  return vault.get(fileId) || null;
}
export function hasFileKey(fileId) {
  return vault.has(fileId);
}