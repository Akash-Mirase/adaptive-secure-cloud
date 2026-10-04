// Holds the UNLOCKED Master Key AND the unlocked sharing PRIVATE key for
// this tab only (see Phase 8's original rationale — nothing here changes:
// never persisted, never sent anywhere, lost on reload by design).
let masterKey = null;
let privateKey = null;

export function setMasterKey(key) { masterKey = key; }
export function getMasterKey() { return masterKey; }

export function setPrivateKey(key) { privateKey = key; }
export function getPrivateKey() { return privateKey; }

export function clearMasterKey() { masterKey = null; privateKey = null; }
export function isUnlocked() { return masterKey !== null; }