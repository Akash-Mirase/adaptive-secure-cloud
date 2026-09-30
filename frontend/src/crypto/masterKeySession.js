// Holds the UNLOCKED Master Key (a CryptoKey, not raw bytes) for this tab
// only, in a module-level variable. It is:
//  - never written to sessionStorage/localStorage/IndexedDB
//  - never sent to the server
//  - cleared on logout, on explicit "lock", and lost (by design) on page reload
// A page reload requires the password again to re-derive the KEK and unwrap
// the Master Key fresh — this module never persists the unlocked state.
let masterKey = null;

export function setMasterKey(key) { masterKey = key; }
export function getMasterKey() { return masterKey; }
export function clearMasterKey() { masterKey = null; }
export function isUnlocked() { return masterKey !== null; }